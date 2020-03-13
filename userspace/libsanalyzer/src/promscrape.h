#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>

#include "coclient.h"
#include "agent-prom.grpc.pb.h"
#include "agent-prom.pb.h"
#include "draios.pb.h"
#include "prometheus.h"
#include "analyzer_settings.h"
#include "analyzer_utils.h"
#include "metric_limits.h"
#include <thread_safe_container/blocking_queue.h>
#include <mutex>

class promscrape {
public:
	typedef std::map<std::string, std::string> tag_map_t;
	typedef struct {
		int pid;
		std::string url;
		std::string container_id;
		uint64_t config_ts;
		uint64_t data_ts;
		uint64_t last_total_samples;
		tag_map_t add_tags;
	} prom_job_config;

	// Map from process-id to job-ids
	typedef std::map<int, std::list<int64_t>> prom_pid_map_t;
	// Map from job_id to job config
	typedef std::map<int64_t, prom_job_config> prom_jobid_map_t;
	// Map from job_id to scrape results
	typedef std::map<int64_t, std::shared_ptr<agent_promscrape::ScrapeResult>> prom_metric_map_t;

	// Hack to get dynamic interval from dragent without adding dependency
	typedef std::function<int()> interval_cb_t;

	// jobs that haven't been used for this long will be pruned.
	const int job_prune_time_s = 60;

	static type_config<bool>c_use_promscrape;
	static type_config<bool>c_export_fastproto;

	explicit promscrape(metric_limits::sptr_t ml, const prometheus_conf &prom_conf, bool threaded, interval_cb_t interval_cb);

	// next() needs to be called from the main thread on a regular basis.
	// With threading enabled it just updates the current timestamp.
	// Without threading it will also call into next_th()
	void next(uint64_t ts);
	// next_th() manages the GRPC connections and processes the queues.
	// Only needs to be called explicitly if threading is enabled, on its own thread.
	void next_th();

	// sendconfig() queues up scrape target configs. Without threadig the configs will get sent
	// immediately. With threading they will get sent during a call to next_th()
	void sendconfig(const vector<prom_process> &prom_procs);

	// pid_has_jobs returns whether or not scrape jobs exist for the given pid.
	bool pid_has_jobs(int pid);

	// pid_to_protobuf() packs prometheus metrics for the given pid into
	// the protobuf "proto" by calling job_to_protobuf() for every job.
	// "limit" indicates the limit of metrics that can still be added to the protobuf
	// The number of metrics added is deducted from "limit" and returned.
	// "filtered" and "total" will be set to the number of metrics that passed
	// the metric filter and the total number before filtering.
	// metric is either an draiosproto::app_metric or prometheus_metric
	template<typename metric>
	unsigned int pid_to_protobuf(int pid, metric *proto,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total);
	template<typename metric>
	unsigned int job_to_protobuf(int64_t job_id, metric *proto,
		unsigned int &limit, unsigned int max_limit,
		unsigned int *filtered, unsigned int *total);
private:
	void sendconfig_th(const vector<prom_process> &prom_procs);

	bool started();
	void try_start();
	void reset();
	void start();
	int64_t assign_job_id(int pid, const std::string &url,
		const std::string &container_id, const tag_map_t &tags, uint64_t ts);
	void addscrapeconfig(agent_promscrape::Config &config, int pid, const std::string &url,
		const std::string &container_id, const std::map<std::string, std::string> &options,
		uint16_t port, const tag_map_t &tags, uint64_t ts);
	void settargetauth(agent_promscrape::Target *target,
		const std::map<std::string, std::string> &options);
	void applyconfig(agent_promscrape::Config &config);
	void handle_result(agent_promscrape::ScrapeResult &result);
	void prune_jobs(uint64_t ts);

	std::shared_ptr<agent_promscrape::ScrapeResult> get_job_result_ptr(uint64_t job_id,
		prom_job_config *config_copy);

	// Mutex to protect all 3 maps, might want finer granularity some day
	std::mutex m_map_mutex;
	prom_metric_map_t m_metrics;
	prom_jobid_map_t m_jobs;
	prom_pid_map_t m_pids;

	std::string m_sock;
	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_start_conn;
	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_config_conn;

	std::unique_ptr<streaming_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncGetData)> m_grpc_start;
	std::unique_ptr<unary_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncApplyConfig)> m_grpc_applyconfig;

	run_on_interval m_start_interval;

	std::atomic<uint64_t> m_next_ts;
	uint64_t m_last_ts;
	bool m_start_failed = false;

	metric_limits::sptr_t m_metric_limits;
	bool m_threaded;
	prometheus_conf m_prom_conf;

	thread_safe_container::blocking_queue<vector<prom_process>> m_config_queue;
	vector<prom_process> m_last_prom_procs;
	interval_cb_t m_interval_cb;
	uint64_t m_last_proto_ts;

	friend class test_helper;
};
