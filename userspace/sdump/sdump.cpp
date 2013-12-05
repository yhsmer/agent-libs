#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#pragma warning(disable: 4996)
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#endif

bool ctrl_c_pressed = false;

static void signal_callback(int signal)
{
	ctrl_c_pressed = true;
}

class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};

//
// Event processing loop
//
captureinfo do_inspect(sinsp* inspector, 
					   uint64_t cnt, 
					   bool quiet, 
					   bool absolute_times,
					   uint64_t emit_stats_every_x_sec,
					   string format)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
//	uint64_t n_printed_evts = 0;
	uint64_t ts;
	uint64_t deltats = 0;
	uint64_t firstts = 0;
	uint64_t screents;
	string line;
	sinsp_evt_formatter formatter(format, inspector);

	//
	// Loop through the events
	//
	while(1)
	{
		if(retval.m_nevts == cnt || ctrl_c_pressed)
		{
			break;
		}

		res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			cerr << "res = " << res << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		retval.m_nevts++;

		ts = ev->get_ts();
		if(firstts == 0)
		{
			firstts = ts;
		}
		deltats = ts - firstts;

		if(absolute_times)
		{
			screents = ts;
		}
		else
		{
			screents = deltats;
		}

		//
		// When the quiet flag is specified, we don't do any kind of processing other
		// than counting the events.
		//
		if(quiet)
		{
			continue;
		}

		//
		// Output the line
		//
		//ev->tostring(&line);
		formatter.tostring(ev, &line);

		cout << line << endl;
	}

	retval.m_time = deltats;
	return retval;
}

static void usage(char *program_name)
{
	fprintf(stderr, "%s [ -r filename ]\n", program_name);
}

static void list_fields()
{
	vector<filter_check_info> fc_plugins;
	sinsp::get_filtercheck_fields_info(&fc_plugins);

	printf("ciao\n");
}

//
// MAIN
//
int main(int argc, char **argv)
{
	string infile;
	string outfile;
	int op;
	uint64_t cnt = -1;
	bool emitjson = false;
	bool quiet = false;
	bool get_stats = false;
	bool absolute_times = false;
	char* transact_fname = NULL;
	double duration = 1;
	captureinfo cinfo;
	string output_format;

	{
		sinsp inspector;
output_format = "%group.name %evt.num)%evt.time.s.%evt.time.ns %evt.cpu %comm (%tid) %evt.dir %evt.name %evt.args";
//output_format = "%evt.num)%evt.arg.res";
//output_format = "%evt.num)";

		//
		// Parse the args
		//
		while((op = getopt(argc, argv, "ac:fhjo:qr:w:")) != -1)
		{
			switch (op)
			{
			case 'a':
				absolute_times = true;
				break;
			case 'c':
				cnt = atoi(optarg);
				if(cnt <= 0)
				{
					fprintf(stderr, "invalid packet count %s\n", optarg);
					return -1;
				}
				break;
			case 'j':
				emitjson = true;
				break;
			case 'h':
				usage(argv[0]);
				return 0;
			case 'f':
				list_fields();
				return 0;
			case 'o':
				output_format = optarg;
				break;
			case 'r':
				infile = optarg;
				break;
			case 'q':
				quiet = true;
				break;
			case 'w':
				outfile = optarg;
				break;
			default:
				break;
			}
		}

		//
		// the filter is specified at the end of the command line
		//
		if(optind < argc)
		{
#ifdef _DEBUG
			string filter;

			for(int32_t j = optind; j < argc; j++)
			{
				filter += argv[j];
				if(j < argc)
				{
					filter += " ";
				}
			}

			inspector.set_filter(filter);
#else
			fprintf(stderr, "filtering not supported in release mode.\n");
			return -1;				
#endif
		}

		//
		// Set the CRTL+C signal
		//
		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting a signal handler.\n");
			return EXIT_FAILURE;
		}

		//
		// Launch the inspeciotn
		//
		try
		{
			if(infile != "")
			{
				inspector.open(infile);
			}
			else
			{
				inspector.open("");
			}

			if(outfile != "")
			{
				inspector.start_dump(outfile);
			}

			duration = ((double)clock()) / CLOCKS_PER_SEC;
			
			cinfo = do_inspect(&inspector, 
				cnt, 
				quiet, 
				get_stats, 
				absolute_times,
				output_format);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;
		}
		catch(sinsp_exception e)
		{
			if(emitjson)
			{
				printf("]\n");
			}

			cerr << e.what() << endl;
		}
		catch(...)
		{
		}

		//
		// If specified on the command line, save the transactions
		//
		if(transact_fname)
		{
			try
			{
				sinsp_transaction_table* ttable = inspector.get_transactions();
				if(ttable)
				{
					ttable->save_json(transact_fname);
				}
				else
				{
					cerr << "error retrieving the transaction table" << endl;
				}
			}
			catch(sinsp_exception e)
			{
				cerr << e.what() << endl;
			}
			catch(...)
			{
			}
		}

		fprintf(stderr, "Elapsed time: %.3lf, %" PRIu64 " events, %.2lf eps\n",
			duration,
			cinfo.m_nevts,
			(double)cinfo.m_nevts / duration);

		fprintf(stderr, "Capture duration: %" PRIu64 ".%" PRIu64 ", %.2lf eps\n",
			cinfo.m_time / 1000000000,
			cinfo.m_time % 1000000000,
			(double)cinfo.m_nevts * 1000000000 / cinfo.m_time);

		if(get_stats)
		{
			inspector.get_stats().emit(stderr);
		}
	}

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif
}
