#include "capture_job_handler.h"
#include "configuration_manager.h"
#include "dragent_message_queues.h"
#include "feature_manager.h"
#include "protocol.h"
#include "sinsp_worker.h"

#include "Poco/DateTimeFormatter.h"
#include "Poco/RWLock.h"
#include "Poco/ScopedLock.h"
#include "Poco/Thread.h"

#include <atomic>
#include <sstream>

using namespace std;
COMMON_LOGGER();

type_config<uint64_t> c_memdump_size(300 * 1024 * 1024, "", "memdump", "size");

type_config<uint32_t> c_memdump_max_init_attempts(10, "", "memdump", "max_init_attempts");
type_config<bool> c_memdump_autodisable(true, "", "memdump", "autodisable", "enabled");
type_config<uint32_t> c_memdump_capture_headers_percentage_threshold(
    60,
    "",
    "memdump",
    "autodisable",
    "capture_headers_percentage_threshold");
type_config<uint64_t> c_memdump_min_time_between_switch_states_ms(
    150,
    "",
    "memdump",
    "autodisable",
    "min_time_between_switch_states_ms");
type_config<uint32_t> c_memdump_re_enable_interval_minutes(30,
                                                           "",
                                                           "memdump",
                                                           "autodisable",
                                                           "re_enable_interval_minutes");
class capture_job
{
public:
	enum state
	{
		ST_INPROGRESS = 0,
		ST_DONE_OK = 1,
		ST_DONE_ERROR = 2,
	};

	capture_job(capture_job_handler* handler,
	            dragent_configuration* configuration,
	            sinsp_memory_dumper* memdumper,
	            std::shared_ptr<timer_thread> timer_thread,
	            uint64_t keepalive_interval_ns,
	            uint64_t max_chunk_size);

	virtual ~capture_job();

	// job_state actually contains the pointer this--we pass the
	// SharedPointer to keep the chain of related std::shared_ptr
	// objects intact.
	bool start(sinsp* inspector,
	           string& token,
	           const capture_job_queue_handler::start_job_details& details,
	           string& errstr,
	           std::shared_ptr<capture_job>& job_state);
	void stop(bool remove_unsent_job = false);
	void send_start();
	void flush(uint64_t ts, bool& throttled);

	void process_event(sinsp_evt* evt);

	bool is_complete();

	const string& token();

	uint64_t start_ns();

private:
	void log_information(const string& msg);
	void log_debug(const string& msg);
	void log_error(const string& msg);

	bool send_dump_chunks(uint64_t ts_ns);
	void read_chunk();

	// These don't change after initialization/start.
	capture_job_handler* m_handler;
	dragent_configuration* m_configuration;
	sinsp_memory_dumper* m_memdumper;
	uint64_t m_max_chunk_size;
	string m_token;
	sinsp_dumper* m_dumper;
	sinsp_filter* m_filter;
	uint64_t m_start_ns;
	uint64_t m_duration_ns;
	uint64_t m_max_size;
	uint64_t m_past_duration_ns;
	uint64_t m_past_size;
	bool m_delete_file_when_done;
	bool m_send_file;
	bool m_defer_send;
	string m_notification_desc;
	string m_file;

	// This is only modified in flush() or the destructor
	// (i.e. the job handler thread).
	FILE* m_fp;

	// This can be read in process_event and written in flush(),
	// which are in different threads.
	atomic<uint64_t> m_file_size;
	atomic<uint64_t> m_n_events;
	atomic<state> m_state;

	// These are only read/written from flush()/cleanup_jobs()
	run_on_interval m_keepalive_interval;
	uint64_t m_last_chunk_offset;
	uint64_t m_last_chunk_idx;
	string m_last_chunk;
	std::shared_ptr<serialized_buffer> m_last_dump_queue_item;

	// Prevents stop() and process_event() from being called
	// simultaneously from different threads.
	Poco::Mutex m_mtx;

	std::shared_ptr<timer_thread> m_timer_thread;
	std::unique_ptr<TimerEvent<Callback>> m_deadline_timer;
};

capture_job::capture_job(capture_job_handler* handler,
                         dragent_configuration* configuration,
                         sinsp_memory_dumper* memdumper,
                         std::shared_ptr<timer_thread> timer_thread,
                         uint64_t keepalive_interval_ns,
                         uint64_t max_chunk_size)
    : m_handler(handler),
      m_configuration(configuration),
      m_memdumper(memdumper),
      m_max_chunk_size(max_chunk_size),
      m_dumper(NULL),
      m_filter(NULL),
      m_start_ns(0),
      m_duration_ns(0),
      m_max_size(0),
      m_past_duration_ns(0),
      m_past_size(0),
      m_delete_file_when_done(true),
      m_send_file(true),
      m_defer_send(false),
      m_fp(NULL),
      m_file_size(0),
      m_n_events(0),
      m_state(ST_INPROGRESS),
      m_keepalive_interval(keepalive_interval_ns),
      m_last_chunk_offset(0),
      m_last_chunk_idx(0),
      m_timer_thread(timer_thread),
      m_deadline_timer(nullptr)
{
}

capture_job::~capture_job()
{
	delete m_dumper;
	delete m_filter;

	if (m_fp)
	{
		fclose(m_fp);
	}

	if (m_delete_file_when_done && !m_file.empty())
	{
		File f(m_file);
		if (f.exists())
		{
			f.remove();
		}
	}
}

bool capture_job::start(sinsp* inspector,
                        string& token,
                        const capture_job_queue_handler::start_job_details& details,
                        string& errstr,
                        std::shared_ptr<capture_job>& job_state)
{
	if (!details.m_filter.empty())
	{
		try
		{
			sinsp_filter_compiler compiler(inspector, details.m_filter);
			m_filter = compiler.compile();
		}
		catch (sinsp_exception& e)
		{
			errstr = e.what();
			return false;
		}
	}

	m_token = token;
	m_file = details.m_file;
	m_duration_ns = details.m_duration_ns;
	m_max_size = details.m_max_size;
	m_past_duration_ns = details.m_past_duration_ns;
	m_delete_file_when_done = details.m_delete_file_when_done;
	m_send_file = details.m_send_file;
	m_defer_send = details.m_defer_send;
	m_notification_desc = details.m_notification_desc;

	// If the start time is unspecified, it's set to the last
	// event time, or if that fails the current time.
	if (details.m_start_ns != 0)
	{
		m_start_ns = details.m_start_ns;
	}
	else
	{
		if (m_handler->m_last_event_ns != 0)
		{
			m_start_ns = m_handler->m_last_event_ns;
		}
		else
		{
			m_start_ns = sinsp_utils::get_current_time_ns();
		}
	}

	log_information(string("starting ") +
	                (details.m_past_duration_ns == 0 ? "standard" : "memdump") + " file=" + m_file +
	                ", filter='" + details.m_filter + "'" +
	                ", defer_send=" + (m_defer_send ? "true" : "false"));

	if(m_timer_thread != nullptr)
	{
		m_deadline_timer = make_unique<TimerEvent<Callback>>([this]() {
			log_debug("Capture duration reached.");
			stop();
			m_deadline_timer = nullptr;
		});
		m_timer_thread->schedule(m_deadline_timer.get(), m_duration_ns);
	}

	if (details.m_past_duration_ns == 0)
	{
		m_dumper = details.m_dumper;
		m_handler->add_job(job_state);
	}
	else
	{
		// We inject a notification to make it easier to identify the starting point.
		if (m_notification_desc.empty())
		{
			m_notification_desc = "starting capture job " + token;
		}

		m_handler->push_notification(m_start_ns,
		                             (details.m_notification_pid ? details.m_notification_pid : 0),
		                             token,
		                             details.m_notification_desc);

		// This will create a file on disk that is the result
		// of the applying the filter against the events held
		// in memory. Afterward, it can be treated like a
		// normal capture job.
		sinsp_memory_dumper_job* memjob = m_memdumper->add_job(m_start_ns,
		                                                       m_file,
		                                                       details.m_filter,
		                                                       m_past_duration_ns,
		                                                       m_duration_ns,
		                                                       &(m_handler->m_membuf_mtx));

		if (memjob->m_state == sinsp_memory_dumper_job::ST_DONE_ERROR)
		{
			m_state = ST_DONE_ERROR;
			errstr = memjob->m_lasterr;
			delete memjob;
			return false;
		}

		// We want the sinsp_dumper from memjob, but otherwise
		// we can immediately delete it.
		m_n_events = memjob->m_n_events;
		m_dumper = memjob->m_dumper;
		memjob->m_dumper = NULL;
		delete memjob;

		// Set the inspector of the dumper to the live
		// inspector. This inspector is only used to hold
		// things like error messages, but should be valid.
		m_dumper->set_inspector(m_handler->m_inspector);

		// Before releasing the memdumper lock, lock the list
		// of jobs and add this job to the list. Otherwise
		// there's a brief window where events could be
		// handled by process_event but *not* be handled by
		// this job.
		m_handler->add_job(job_state);
		m_handler->m_membuf_mtx.unlock();
	}

	m_fp = fopen(m_file.c_str(), "r");
	if (m_fp == NULL)
	{
		errstr = strerror(errno);
		return false;
	}

	// If configured, send a keepalive message now.
	if (details.m_send_initial_keepalive)
	{
		draiosproto::dump_response response;
		m_handler->prepare_response(m_token, &response);
		response.set_keep_alive(true);
		log_debug("sending keepalive");
		m_handler->queue_response(response, protocol_queue::BQ_PRIORITY_HIGH);
	}

	return true;
}

void capture_job::stop(bool remove_unsent_job)
{
	Poco::ScopedLock<Poco::Mutex> lck(m_mtx);

	if (m_state != ST_INPROGRESS)
	{
		return;
	}

	log_information("stopped. captured events: " + NumberFormatter::format(m_n_events));

	if (m_past_duration_ns != 0 && m_memdumper == NULL)
	{
		m_handler->send_error(
		    m_token,
		    "memory dump corrupted in the agent. Cannot perform back in time capture.");
		ASSERT(false);
		return;
	}
	//
	// Stop the job, but don't delete it yet, there might be
	// a bunch of pending chunks
	//
	m_state = ST_DONE_OK;

	// If defer_send is true, this means that this job was stopped
	// before send_start() was called. In this case, we send
	// nothing at all.
	if (m_defer_send && remove_unsent_job)
	{
		m_send_file = false;
	}

	// Delete the dumper so any pending data is written to the file.
	delete m_dumper;
	m_dumper = NULL;
}

void capture_job::send_start()
{
	Poco::ScopedLock<Poco::Mutex> lck(m_mtx);

	log_debug("send_start");

	m_defer_send = false;
}

void capture_job::flush(uint64_t ts, bool& throttled)
{
	log_debug("flushing");

	m_keepalive_interval.run(
	    [this, ts]() {
		    // Send keepalives once we've sent at least one chunk
		    if (m_send_file && m_last_chunk_idx > 0)
		    {
			    draiosproto::dump_response response;
			    m_handler->prepare_response(m_token, &response);
			    response.set_keep_alive(true);
			    log_debug("sending keepalive");
			    m_handler->queue_response(response, protocol_queue::BQ_PRIORITY_HIGH);
		    }
	    },
	    ts);

	if (m_state != ST_DONE_ERROR)
	{
		struct stat st;
		if (stat(m_file.c_str(), &st) != 0)
		{
			log_error("error checking file size");
			m_handler->send_error(m_token, "Error checking file size");
			m_state = ST_DONE_ERROR;
			ASSERT(false);
		}

		m_file_size = st.st_size;
	}

	// Note that if any job is throttled while
	// iterating over the vector of jobs, the
	// remaining jobs are considered throttled
	// until the next call to flush_jobs().
	if ((m_state == ST_INPROGRESS || m_state == ST_DONE_OK) && m_send_file && !m_defer_send &&
	    !throttled)
	{
		if (!send_dump_chunks(ts))
		{
			throttled = true;
		}
	}
}

void capture_job::process_event(sinsp_evt* ev)
{
	Poco::ScopedLock<Poco::Mutex> lck(m_mtx);

	if (m_state != ST_INPROGRESS)
	{
		return;
	}

	if (m_max_size && m_file_size > m_max_size)
	{
		log_debug("Max capture size reached.");
		stop();
		return;
	}

	ASSERT(ev->get_ts() >= m_start_ns);
	if (ev->get_ts() < m_start_ns)
	{
		log_error("Ignoring event " + to_string(ev->get_ts()) + " before capture start time " +
		          to_string(m_start_ns));
		return;
	}

	if (ev->get_ts() - m_start_ns > m_duration_ns)
	{
		log_debug("Capture duration reached.");
		stop();
		return;
	}

	bool current_filtered_out = ev->m_filtered_out;
	if (m_filter != NULL)
	{
		if (!m_filter->run(ev))
		{
			ev->m_filtered_out = true;
		}
	}

	bool do_drop;
	(void)ev->get_dump_flags(&do_drop);
	ev->m_filtered_out = current_filtered_out;

	if (do_drop)
	{
		return;
	}

	m_dumper->dump(ev);
	++m_n_events;
}

bool capture_job::is_complete()
{
	return (m_state == ST_DONE_ERROR ||
	        (m_state == ST_DONE_OK && (!m_send_file || m_last_chunk_offset >= m_file_size)));
}

const string& capture_job::token()
{
	return m_token;
}

uint64_t capture_job::start_ns()
{
	return m_start_ns;
}

void capture_job::log_information(const string& msg)
{
	LOG_INFO("job " + m_token + ": " + msg);
}

void capture_job::log_debug(const string& msg)
{
	LOG_DEBUG("job " + m_token + ": " + msg);
}

void capture_job::log_error(const string& msg)
{
	LOG_ERROR("job " + m_token + ": " + msg);
}

bool capture_job::send_dump_chunks(uint64_t ts_ns)
{
	ASSERT(m_last_chunk_offset <= m_file_size);

	// For in progress jobs, we stop when there is less than a
	// chunk remaining. Otherwise, we continue until we've sent
	// everything.

	stringstream ss;
	ss << "In send_dump_chunks\n"
	   << "\tFile size: " << m_file_size << "\n"
	   << "\tLast chunk offset: " << m_last_chunk_offset << "\n"
	   << "\tBytes available: " << (m_file_size - m_last_chunk_offset) << "\n"
	   << "\tMax chunk size: " << m_max_chunk_size << "\n"
	   << "\tState: " << (int)m_state;
	log_debug(ss.str());
	ss.str("");
	ss.clear();

	while (m_last_chunk_offset < m_file_size &&
	       (m_state == ST_DONE_OK || m_file_size - m_last_chunk_offset > m_max_chunk_size))
	{
		if (m_last_chunk.empty())
		{
			read_chunk();
		}

		uint32_t progress = 0;
		ASSERT(m_file_size > 0);
		if (m_file_size > 0)
		{
			progress = (m_last_chunk_offset * 100) / m_file_size;
		}

		if (!m_last_dump_queue_item)
		{
			draiosproto::dump_response response;
			m_handler->prepare_response(m_token, &response);
			response.set_content(m_last_chunk);
			response.set_chunk_no(m_last_chunk_idx);

			ASSERT(m_last_chunk_offset + m_last_chunk.size() <= m_file_size);
			if (m_last_chunk_offset + m_last_chunk.size() >= m_file_size)
			{
				response.set_final_chunk(true);
			}

			if (m_state != ST_INPROGRESS)
			{
				response.set_final_size_bytes(m_file_size);
			}

			m_last_dump_queue_item = m_handler->dump_response_to_queue_item(response);
		}

		// In order to queue the response, there must be
		// sufficient bandwith avaiable in the token bucket
		// and the queue must not be full.
		if (!m_handler->can_send(m_last_dump_queue_item->buffer.size(), ts_ns))
		{
			log_debug("throttled while sending chunk " + NumberFormatter::format(m_last_chunk_idx) +
			          ", will retry");
			return false;
		}

		if (!m_handler->queue_item(m_last_dump_queue_item, protocol_queue::BQ_PRIORITY_LOW))
		{
			log_debug("queue full while sending chunk " +
			          NumberFormatter::format(m_last_chunk_idx) + ", will retry");
			return false;
		}

		log_debug("sent chunk " + NumberFormatter::format(m_last_chunk_idx) + " of size " +
		          NumberFormatter::format(m_last_chunk.size()) + ", progress " +
		          NumberFormatter::format(progress) + "%%");

		++m_last_chunk_idx;
		m_last_chunk_offset += m_last_chunk.size();
		m_last_chunk.clear();
		m_last_dump_queue_item = NULL;
	}

	return true;
}

void capture_job::read_chunk()
{
	Buffer<char> buffer(16384);
	uint64_t chunk_size = m_max_chunk_size;
	bool eof = false;

	while (!eof && chunk_size)
	{
		size_t to_read = min<u_int64_t>(buffer.size(), chunk_size);
		ASSERT(m_fp);
		size_t res = fread(buffer.begin(), 1, to_read, m_fp);
		if (res != to_read)
		{
			if (feof(m_fp))
			{
				log_debug("EOF");
				eof = true;
			}
			else if (ferror(m_fp))
			{
				log_error("ferror while reading " + m_file);
				m_state = ST_DONE_ERROR;
				m_handler->send_error(m_token, "ferror while reading " + m_file);
				ASSERT(false);
				return;
			}
			else
			{
				log_error("unknown error while reading " + m_file);
				m_state = ST_DONE_ERROR;
				m_handler->send_error(m_token, "unknown error while reading " + m_file);
				ASSERT(false);
				return;
			}
		}

		chunk_size -= res;
		m_last_chunk.append(buffer.begin(), res);
	}

	// Now that event processing occurs in a different thread,
	// it's actually possible that we read a chunk past the end of
	// the file size found in the fstat. If we do, update m_file_size here.
	if ((m_last_chunk_offset + m_last_chunk.size()) > m_file_size)
	{
		m_file_size = m_last_chunk_offset + m_last_chunk.size();
	}
}

const string capture_job_handler::m_name = "capture_job_handler";
const uint64_t capture_job_handler::default_max_chunk_size = 100 * 1024;
const uint64_t capture_job_handler::m_keepalive_interval_ns = 30 * 1000000000LL;

capture_job_handler::capture_job_handler(dragent_configuration* configuration,
                                         protocol_queue* queue,
                                         std::shared_ptr<timer_thread> timer_thread)
    : running_state_runnable("capture_job_manager"),
      m_sysdig_pid(getpid()),
      m_sysdig_sid(0),
      m_log_stats_interval(10000000000),
      m_inspector(NULL),
      m_configuration(configuration),
      m_queue(queue),
      m_max_chunk_size(default_max_chunk_size),
      m_dump_job_requests(10),
      m_last_job_check_ns(0),
      m_last_event_ns(0),
      m_job_in_progress(false),
      m_timer_thread(timer_thread)
{
}

capture_job_handler::~capture_job_handler() {}

void capture_job_handler::init(const sinsp* inspector)
{
	m_inspector = (sinsp*)inspector;
	if (m_configuration->m_sysdig_capture_enabled)
	{
		// The burst size should be at least as big as the
		// tokens gained during one loop through run(), which
		// currently runs every 200ms. We set it to 1/4 the
		// token gain rate.
		m_sysdig_captures_tb.init(m_configuration->m_sysdig_capture_transmit_rate,
		                          m_configuration->m_sysdig_capture_transmit_rate / 4.0);
	}

	if (feature_manager::instance().get_enabled(MEMDUMP))
	{
		LOG_INFO(m_name +
		         ": enabling memdump, size=" + to_string(c_memdump_size.get_value()));
		m_memdumper = make_unique<sinsp_memory_dumper>((sinsp*)inspector);
		m_memdumper->init(c_memdump_size.get_value(),
		                  c_memdump_size.get_value(),
		                  c_memdump_max_init_attempts.get_value(),
		                  c_memdump_autodisable.get_value(),
		                  c_memdump_capture_headers_percentage_threshold.get_value(),
		                  c_memdump_min_time_between_switch_states_ms.get_value(),
		                  c_memdump_re_enable_interval_minutes.get_value());
	}

	//
	// Initialize the underlying scap notification event and set
	// the inspector for the sinsp-level event. We'll fill in the
	// rest of the sinsp-level event when we set the type.
	//
	m_notification_scap_evt = (scap_evt*)m_notification_scap_evt_storage;
	m_notification_evt.m_inspector = m_inspector;
}

void capture_job_handler::do_run()
{
	while (heartbeat())
	{
		uint32_t sleep_ms = 200;
		m_last_job_check_ns = sinsp_utils::get_current_time_ns();

		m_log_stats_interval.run(
		    [this]() {
			    uint32_t num_jobs = 0;
			    uint64_t oldest = m_last_job_check_ns;
			    {
				    Poco::ScopedReadRWLock jobs_lck(m_jobs_lock);
				    num_jobs = m_jobs.size();

				    for (auto& job : m_jobs)
				    {
					    if (job->start_ns() < oldest)
					    {
						    oldest = job->start_ns();
					    }
				    }
			    }
			    if (num_jobs > 0)
			    {
				    LOG_INFO(
				        "capture_jobs: nj=" + to_string(num_jobs) +
				        " oldest_delta_ms=" + to_string((m_last_job_check_ns - oldest) / 1000000));
			    }
		    },
		    m_last_job_check_ns);

		process_job_requests();

		flush_jobs(m_last_job_check_ns);
		cleanup_jobs(m_last_job_check_ns);

		Thread::sleep(sleep_ms);
	}

	cleanup();
}

void capture_job_handler::process_event(sinsp_evt* ev)
{
	m_last_event_ns = ev->get_ts();

	//
	// We don't want dragent to show up in captures
	//

	if (m_sysdig_sid == 0)
	{
		m_sysdig_sid = getsid(0);
	}

	sinsp_threadinfo* tinfo = ev->get_thread_info();

	if (!m_configuration->m_capture_dragent_events && tinfo && tinfo->m_sid == m_sysdig_sid)
	{
		return;
	}

	//
	// If required, dump the event in the memory circular buffer
	//
	if (feature_manager::instance().get_enabled(MEMDUMP))
	{
		Poco::ScopedLock<Poco::Mutex> lck(m_membuf_mtx);
		m_memdumper->process_event(ev);
	}

	{
		Poco::ScopedReadRWLock jobs_lck(m_jobs_lock);

		for (auto& job : m_jobs)
		{
			job->process_event(ev);
		}
	}
}

bool capture_job_handler::queue_job_request(sinsp* inspector,
                                            std::shared_ptr<dump_job_request> job_request,
                                            string& errstr)
{
	Poco::ScopedReadRWLock jobs_lck(m_jobs_lock);

	// If the number of captures PLUS the number of capture job
	// requests is greater than m_max_sysdig_captures, return an
	// error immediately.
	if (job_request->m_request_type == dump_job_request::JOB_START &&
	    (m_jobs.size() + m_dump_job_requests.size()) >= m_configuration->m_max_sysdig_captures)
	{
		errstr = "maximum number of outstanding captures (" +
		         to_string(m_configuration->m_max_sysdig_captures) + ") reached";
		return false;
	}

	LOG_INFO(m_name + ": scheduling job request type=" +
	                   dump_job_request::request_type_str(job_request->m_request_type) +
	                   ", token= " + job_request->m_token);

	// If doing a traditional (i.e. not back-in-time) capture,
	// create a sinsp_dumper tied to the provided inspector and
	// include it in the job request.
	if (job_request->m_request_type == dump_job_request::JOB_START)
	{
		if (!job_request->m_start_details)
		{
			errstr = "no details provided for start job";
			return false;
		}

		job_request->m_start_details->m_file =
		    m_configuration->m_dump_dir + job_request->m_token + ".scap";

		if (job_request->m_start_details->m_past_duration_ns == 0)
		{
			sinsp_dumper* dumper = new sinsp_dumper(inspector);
			dumper->open(job_request->m_start_details->m_file, true, true);
			job_request->m_start_details->m_dumper = dumper;
		}
	}

	if (!m_dump_job_requests.put(job_request))
	{
		if (job_request->m_start_details && job_request->m_start_details->m_dumper)
		{
			delete job_request->m_start_details->m_dumper;
			job_request->m_start_details->m_dumper = NULL;
		}
		errstr = "Capture job handler queue full";
		return false;
	}

	return true;
}

void capture_job_handler::cleanup()
{
	LOG_INFO(m_name + ": cleaning up, force=" + string(m_force_cleanup ? "yes" : "no"));

	// Stop all jobs
	{
		Poco::ScopedWriteRWLock jobs_lck(m_jobs_lock);
		for (auto& job : m_jobs)
		{
			job->stop();
		}
	}

	m_last_job_check_ns = sinsp_utils::get_current_time_ns();

	// Flush all state. Due to throttling, it's possible that this
	// may take more than one attempt. We try up to 10 times
	// before giving up.
	if (!m_force_cleanup)
	{
		uint32_t attempt = 0;

		while (attempt < 10 && m_jobs.size() > 0)
		{
			flush_jobs(m_last_job_check_ns);
			cleanup_jobs(m_last_job_check_ns);

			Thread::sleep(200);
		}
	}

	if (m_jobs.size() > 0)
	{
		Poco::ScopedWriteRWLock jobs_lck(m_jobs_lock);
		LOG_WARNING(m_name + ": " + to_string(m_jobs.size()) +
		               " jobs remaining, deleting anyway");

		m_jobs.clear();
	}
}

void capture_job_handler::process_job_requests()
{
	std::shared_ptr<dump_job_request> request;
	while (m_dump_job_requests.get(&request, 0))
	{
		LOG_DEBUG(m_name + ": dequeued dump request type=" +
		             dump_job_request::request_type_str(request->m_request_type) +
		             " token=" + request->m_token);
		switch (request->m_request_type)
		{
		case dump_job_request::JOB_START:

			if (!request->m_start_details)
			{
				send_error(request->m_token, "no details provided for start job");
				return;
			}

			if (request->m_start_details->m_duration_ns == 0 &&
			    request->m_start_details->m_past_duration_ns == 0)
			{
				send_error(request->m_token, "either duration or past_duration must be nonzero");
				return;
			}

			// As a resource exaustion prevention
			// mechanism, only allow "max sysdig captures"
			// to be outstanding at one time.
			if (m_jobs.size() >= m_configuration->m_max_sysdig_captures)
			{
				send_error(request->m_token,
				           "maximum number of outstanding captures (" +
				               to_string(m_configuration->m_max_sysdig_captures) + ") reached");
				return;
			}

			start_job(request->m_token, *(request->m_start_details));

			break;
		case dump_job_request::JOB_STOP:
		{
			Poco::ScopedReadRWLock jobs_lck(m_jobs_lock);

			bool found = false;

			for (auto& job : m_jobs)
			{
				if (job->token() == request->m_token)
				{
					job->stop(request->m_stop_details->m_remove_unsent_job);
					found = true;
					break;
				}
			}

			if (!found)
			{
				LOG_ERROR(m_name + ": can't find job " + request->m_token);
			}

			break;
		}
		case dump_job_request::JOB_SEND_START:
		{
			Poco::ScopedReadRWLock jobs_lck(m_jobs_lock);

			bool found = false;

			for (auto& job : m_jobs)
			{
				if (job->token() == request->m_token)
				{
					job->send_start();
					found = true;
					break;
				}
			}

			if (!found)
			{
				LOG_ERROR(m_name + ": can't find job " + request->m_token);
			}

			break;
		}
		default:
			ASSERT(false);
		}
	}
}

void capture_job_handler::start_job(string& token, const start_job_details& details)
{
	std::shared_ptr<capture_job> job_state = make_shared<capture_job>(this,
	                                                                  m_configuration,
	                                                                  m_memdumper.get(),
	                                                                  m_timer_thread,
	                                                                  m_keepalive_interval_ns,
	                                                                  m_max_chunk_size);
	string errstr;

	if (m_configuration->m_sysdig_capture_enabled == false)
	{
		send_error(token,
		           "Sysdig capture disabled from agent configuration file, not starting capture");
		return;
	}

	if (this->m_inspector->is_nodriver())
	{
		send_error(token, "Sysdig Agent in nodriver mode, captures not supported");
		return;
	}

	if (details.m_past_duration_ns != 0 &&
	    (!feature_manager::instance().get_enabled(MEMDUMP) ||
             !(m_memdumper && m_memdumper->is_enabled())))
	{
		send_error(token,
		           string("memory dump functionality not enabled in the target agent ") +
		               string("configured=") +
		               (feature_manager::instance().get_enabled(MEMDUMP) ? "true" : "false") +
		               string(" enabled=") + (m_memdumper && m_memdumper->is_enabled() ? "true" : "false") +
		               string(". Cannot perform back in time capture."));
		return;
	}

	// If there were no capture jobs previously, and now there
	// are, tell the sinsp_worker to disable drop mode.
	if (m_jobs.size() == 0)
	{
		m_job_in_progress = true;
	}

	if (!job_state->start(m_inspector, token, details, errstr, job_state))
	{
		LOG_ERROR(m_name + ": could not start capture job " + token + ": " + errstr);
		send_error(token, errstr);

		if (m_jobs.size() == 0)
		{
			m_job_in_progress = false;
		}
		return;
	}
}

void capture_job_handler::add_job(std::shared_ptr<capture_job>& job)
{
	Poco::ScopedWriteRWLock jobs_lck(m_jobs_lock);
	m_jobs.push_back(job);
}

void capture_job_handler::flush_jobs(uint64_t ts)
{
	bool throttled = false;
	{
		Poco::ScopedReadRWLock jobs_lck(m_jobs_lock);

		for (auto& job : m_jobs)
		{
			job->flush(ts, throttled);
		}
	}

	// If any job was throttled, rotate the jobs so the first job
	// is moved to the end. This ensures that there won't be
	// starvation where the first job continually uses the available bandwidth.
	if (throttled)
	{
		Poco::ScopedWriteRWLock jobs_lck(m_jobs_lock);
		rotate(m_jobs.begin(), m_jobs.begin() + 1, m_jobs.end());
	}
}

void capture_job_handler::cleanup_jobs(uint64_t ts)
{
	Poco::ScopedWriteRWLock jobs_lck(m_jobs_lock);
	uint32_t old_size = m_jobs.size();

	vector<std::shared_ptr<capture_job>>::iterator it = m_jobs.begin();

	while (it != m_jobs.end())
	{
		if (it->get()->is_complete())
		{
			LOG_INFO("job " + it->get()->token() + ": removing state");
			it = m_jobs.erase(it);
		}
		else
		{
			++it;
		}
	}

	// If there were any capture jobs previously, and now there
	// are not, tell the sinsp_worker to reenable autodrop mode.
	if (old_size > 0 && m_jobs.size() == 0)
	{
		m_job_in_progress = false;
	}
}

bool capture_job_handler::can_send(uint32_t buffer_size, uint64_t ts_ns)
{
	return m_sysdig_captures_tb.claim(buffer_size, ts_ns);
}

void capture_job_handler::prepare_response(const string& token,
                                           draiosproto::dump_response* response)
{
	response->set_timestamp_ns(sinsp_utils::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->machine_id());
	response->set_token(token);
}

shared_ptr<serialized_buffer> capture_job_handler::dump_response_to_queue_item(
    const draiosproto::dump_response& response)
{
	protocol_compression_method compression =
	    configuration_manager::instance().get_config<bool>("compression.enabled")->get_value()
	        ? protocol_compression_method::GZIP
	        : protocol_compression_method::NONE;
	std::shared_ptr<protobuf_compressor> compressor;
	if (compression == protocol_compression_method::NONE)
	{
		compressor = null_protobuf_compressor::get();
	}
	else
	{
		compressor = gzip_protobuf_compressor::get(-1);
	}

	return dragent_protocol::message_to_buffer(
	    sinsp_utils::get_current_time_ns(),
	    draiosproto::message_type::DUMP_RESPONSE,
	    response,
	    // this is a bit ugly. Ultimately this should be part of the protocol
	    // handler, but moving that functionality is a bear
	    compressor);
}

bool capture_job_handler::queue_item(std::shared_ptr<serialized_buffer>& item,
                                     protocol_queue::item_priority priority)
{
	if (!item)
	{
		LOG_ERROR(m_name + ": NULL converting message to item");
		return true;
	}

	while (!m_queue->put(item, priority))
	{
		LOG_INFO(m_name + ": queue full");
		return false;
	}

	return true;
}

bool capture_job_handler::queue_response(const draiosproto::dump_response& response,
                                         protocol_queue::item_priority priority)
{
	std::shared_ptr<serialized_buffer> item = dump_response_to_queue_item(response);

	return queue_item(item, priority);
}

void capture_job_handler::send_error(const string& token, const string& error)
{
	LOG_ERROR(m_name + ": error from capture job: " + error);
	draiosproto::dump_response response;
	prepare_response(token, &response);
	response.set_error(error);
	queue_response(response, protocol_queue::BQ_PRIORITY_HIGH);
}

void capture_job_handler::push_notification(uint64_t ts,
                                            uint64_t tid,
                                            string id,
                                            string description)
{
	m_notification_scap_evt->ts = ts;
	m_notification_scap_evt->tid = tid;
	m_notification_scap_evt->type = PPME_NOTIFICATION_E;
	m_notification_scap_evt->nparams = 2;
	m_notification_evt.init((uint8_t*)m_notification_scap_evt, 0);

	uint16_t* lens = (uint16_t*)(m_notification_scap_evt_storage + sizeof(struct ppm_evt_hdr));
	uint16_t idlen = id.length() + 1;
	uint16_t desclen = description.length() + 1;
	lens[0] = idlen;
	lens[1] = desclen;

	memcpy((m_notification_scap_evt_storage + sizeof(struct ppm_evt_hdr) + 4), id.c_str(), idlen);

	memcpy((m_notification_scap_evt_storage + sizeof(struct ppm_evt_hdr) + 4 + idlen),
	       description.c_str(),
	       desclen);

	m_notification_scap_evt->len = sizeof(scap_evt) + sizeof(uint16_t) * 2 + idlen + desclen;

	process_event(&m_notification_evt);
}

void capture_job_handler::push_infra_event(uint64_t ts,
                                           uint64_t tid,
                                           const std::string& source,
                                           const std::string& name,
                                           const std::string& description,
                                           const std::string& scope)
{
	uint32_t hdrlen = sizeof(struct ppm_evt_hdr) + 4 * 2;

	m_notification_scap_evt->ts = ts;
	m_notification_scap_evt->tid = tid;
	m_notification_scap_evt->type = PPME_INFRASTRUCTURE_EVENT_E;
	m_notification_scap_evt->nparams = 4;
	m_notification_evt.init((uint8_t*)m_notification_scap_evt, 0);

	uint16_t* lens = (uint16_t*)(m_notification_scap_evt_storage + sizeof(struct ppm_evt_hdr));
	uint16_t sourcelen = source.length() + 1;
	uint16_t namelen = name.length() + 1;
	uint16_t desclen = description.length() + 1;
	uint16_t scopelen = scope.length() + 1;
	lens[0] = sourcelen;
	lens[1] = namelen;
	lens[2] = desclen;
	lens[3] = scopelen;

	memcpy((m_notification_scap_evt_storage + hdrlen), source.c_str(), sourcelen);

	memcpy((m_notification_scap_evt_storage + hdrlen + sourcelen), name.c_str(), namelen);

	memcpy((m_notification_scap_evt_storage + hdrlen + sourcelen + namelen),
	       description.c_str(),
	       desclen);

	memcpy((m_notification_scap_evt_storage + hdrlen + sourcelen + namelen + desclen),
	       scope.c_str(),
	       scopelen);

	m_notification_scap_evt->len =
	    sizeof(scap_evt) + sizeof(uint16_t) * 4 + sourcelen + namelen + desclen + scopelen;

	process_event(&m_notification_evt);
}
