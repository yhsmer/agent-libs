
#include "watchdog_runnable.h"
#include "common_logger.h"
#include "uptime.h"
#include "watchdog_runnable_fatal_error.h"
#include <cinttypes>

COMMON_LOGGER();

watchdog_runnable::watchdog_runnable(const std::string& name, 
	                             const is_terminated_delgate& terminated_delegate) :
	// Purposely initializing heartbeat to 0 so that we can check
	// whether runnable has ever started.
	m_terminated_with_error(false),
	m_last_heartbeat_ms(0),
	m_pthread_id(0),
	m_timeout_ms(0),
	m_name(name),
	is_terminated(terminated_delegate)
{
}

void watchdog_runnable::timeout_ms(uint64_t value_ms)
{
	if(is_started())
	{
		LOG_ERROR("Attempted to set %s timeout after runnable started.",
			  m_name.c_str());
		return;
	}

	m_timeout_ms = value_ms;
}

bool watchdog_runnable::heartbeat()
{
	if(nullptr != is_terminated && is_terminated()) {
		return false;
	}

	m_last_heartbeat_ms = uptime::milliseconds();
	return true;
}

watchdog_runnable::health watchdog_runnable::is_healthy(int64_t& age_ms) const
{
	// Purposely doing this first so that age_ms is recorded
	bool timed_out = is_timed_out(m_name,
				      m_last_heartbeat_ms,
				      m_timeout_ms,
				      age_ms);

	if (!is_component_healthy()) 
	{
		LOG_FATAL("Fatal error occurred in %s. Terminating immediately and restarting.",
			  m_name.c_str());
		return health::FATAL_ERROR;
	}

	if(m_terminated_with_error)
	{
		return health::FATAL_ERROR;
	}

	return timed_out ? health::TIMEOUT : health::HEALTHY;
}

// static
bool watchdog_runnable::is_timed_out(const std::string& name,
				     uint64_t last_heartbeat_ms,
				     uint64_t timeout_ms,
				     int64_t& age_ms)
{
	// This might look odd, but until the heartbeat occurs the first time
	// we always consider the watchdog_runnable to be healthy. This is kept to be
	// consistent with previous implementation.
	if(!last_heartbeat_ms)
	{
		return false;
	}

	age_ms = uptime::milliseconds() - last_heartbeat_ms;

	DBG_LOG_ERROR("watchdog: %s, last activity %" PRId64
	              " ms ago, timeout %" PRIu64 " ms",
	              name.c_str(),
	              age_ms,
		      timeout_ms);

	if(timeout_ms == NO_TIMEOUT)
	{
		return false;
	}

	if(age_ms <= static_cast<int64_t>(timeout_ms))
	{
		return false;
	}

	// Found a timed out watchdog_runnable
	return true;
}

void watchdog_runnable::run()
{
	try
	{
		LOG_INFO("%s starting", m_name.c_str());

		m_pthread_id = pthread_self();
		do_run();
	}
	catch (const watchdog_runnable_fatal_error& ex)
	{
		if(m_name == ex.where())
		{
			LOG_FATAL("Fatal error occurred in %s. Terminating gracefully. Detail: %s",
				  m_name.c_str(),
				  ex.what());
		}
		else
		{
			LOG_FATAL("Fatal error occurred in %s on %s. Terminating gracefully. Detail: %s",
				  ex.where(),
				  m_name.c_str(),
				  ex.what());

		}
		m_terminated_with_error = true;
	}
	catch (const std::exception& ex)
	{
		LOG_FATAL("Unexpected fatal error occurred in %s. Terminating gracefully. Detail: %s",
			  m_name.c_str(),
			  ex.what());
		m_terminated_with_error = true;
	}
	catch (...)
	{
		LOG_FATAL("Unknown fatal error occurred on %s. Terminating gracefully.",
			  m_name.c_str());
		m_terminated_with_error = true;
	}

	LOG_INFO("%s terminating", m_name.c_str());
}

void watchdog_runnable::log_report()
{
	const int64_t age_ms = uptime::milliseconds() - m_last_heartbeat_ms;
	LOG_INFO("%s last activity %" PRId64" ms ago", m_name.c_str(), age_ms);
}
