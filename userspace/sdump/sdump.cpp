#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#ifdef HAS_ANALYZER
#include <analyzer.h>
#endif
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>

#ifdef _WIN32
#pragma warning(disable: 4996)
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#endif

//
// ASSERT implementation
//
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

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
					   string format,
					   sinsp_filter* display_filter)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;
	uint64_t deltats = 0;
	uint64_t firstts = 0;
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
		if(!quiet)
		{
			if(display_filter)
			{
				if(!display_filter->run(ev))
				{
					continue;
				}
			}

			if(formatter.tostring(ev, &line))
			{
				cout << line << endl;
			}
		}
	}

	retval.m_time = deltats;
	return retval;
}

static void usage(char *program_name)
{
	fprintf(stderr, "%s [ -r filename ]\n", program_name);
}

#define DESCRITION_TEXT_START 16
#define CONSOLE_LINE_LEN 79

static void list_fields()
{
	uint32_t j, l, m;
	int32_t k;

	vector<const filter_check_info*> fc_plugins;
	sinsp::get_filtercheck_fields_info(&fc_plugins);

	for(j = 0; j < fc_plugins.size(); j++)
	{
		const filter_check_info* fci = fc_plugins[j];

		printf("\n----------------------\n");
		printf("Field Class: %s\n\n", fci->m_name.c_str());

		for(k = 0; k < fci->m_nfiedls; k++)
		{
			const filtercheck_field_info* fld = &fci->m_fields[k];

			printf("%s", fld->m_name);
			uint32_t namelen = strlen(fld->m_name);

			ASSERT(namelen < DESCRITION_TEXT_START);

			for(l = 0; l < DESCRITION_TEXT_START - namelen; l++)
			{
				printf(" ");
			}
				
			size_t desclen = strlen(fld->m_description);

			for(l = 0; l < desclen; l++)
			{
				if(l % (CONSOLE_LINE_LEN - DESCRITION_TEXT_START) == 0 && l != 0)
				{
					printf("\n");

					for(m = 0; m < DESCRITION_TEXT_START; m++)
					{
						printf(" ");
					}
				}

				printf("%c", fld->m_description[l]);
			}

			printf("\n");
		}
	}
}

//
// MAIN
//
int main(int argc, char **argv)
{
	int res = EXIT_SUCCESS;
	string infile;
	string outfile;
	int op;
	uint64_t cnt = -1;
	bool emitjson = false;
	bool quiet = false;
	bool absolute_times = false;
	bool is_filter_display = false;
	sinsp_filter* display_filter = NULL;
	double duration = 1;
	captureinfo cinfo;
	string output_format;
	uint32_t snaplen = 0;
#ifdef HAS_ANALYZER
	sinsp_analyzer* analyzer = NULL;
#endif

	sinsp* inspector = new sinsp();
#ifdef HAS_ANALYZER
		analyzer = new sinsp_analyzer(inspector);
		inspector->m_analyzer = analyzer;
#endif

	output_format = "*%evt.num)%evt.time.s.%evt.time.ns %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.args";
//		output_format = "%evt.num)%evt.type time:%latencyns";

	//
	// Parse the args
	//
	while((op = getopt(argc, argv, "ac:dhi:jlm:p:qr:s:w:")) != -1)
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
#ifdef HAS_ANALYZER
				delete analyzer;
#endif
				delete inspector;
				return EXIT_FAILURE;
			}
			break;
		case 'd':
			is_filter_display = true;
			break;
		case 'j':
			emitjson = true;
			break;
		case 'h':
			usage(argv[0]);
#ifdef HAS_ANALYZER
			delete analyzer;
#endif
			delete inspector;
			return EXIT_SUCCESS;
		case 'i':
#ifdef HAS_ANALYZER
			if(string(optarg) == "stdout")
			{
				analyzer->get_configuration()->set_log_output_type(sinsp_logger::OT_STDOUT);
			}
			else if(string(optarg) == "stderr")
			{
				analyzer->get_configuration()->set_log_output_type(sinsp_logger::OT_STDERR);
			}
			else if(string(optarg) == "file")
			{
				analyzer->get_configuration()->set_log_output_type(sinsp_logger::OT_FILE);
			}
			else if(string(optarg) == "stdout_nots")
			{
				analyzer->get_configuration()->set_log_output_type((sinsp_logger::output_type)(sinsp_logger::OT_STDOUT | sinsp_logger::OT_NOTS));
			}
			else if(string(optarg) == "stderr_nots")
			{
				analyzer->get_configuration()->set_log_output_type((sinsp_logger::output_type)(sinsp_logger::OT_STDERR | sinsp_logger::OT_NOTS));
			}
			else if(string(optarg) == "file_nots")
			{
				analyzer->get_configuration()->set_log_output_type((sinsp_logger::output_type)(sinsp_logger::OT_FILE | sinsp_logger::OT_NOTS));
			}
			else
			{
				fprintf(stderr, "wrong -i option %s. Accepted values: stdout, sterr or file.", optarg);
#ifdef HAS_ANALYZER
				delete analyzer;
#endif
				delete inspector;
				return -1;
			}
#endif // HAS_ANALYZER

			break;
		case 'l':
			list_fields();
#ifdef HAS_ANALYZER
			delete analyzer;
#endif
			delete inspector;
			return EXIT_SUCCESS;
		case 'm':
#ifdef HAS_ANALYZER
			analyzer->get_configuration()->set_emit_metrics_to_file(true);
			analyzer->get_configuration()->set_metrics_directory(optarg);
#endif
			break;
		case 'p':
			if(string(optarg) == "p")
			{
				//
				// -ff shows the default output format, useful if the user wants to tweak it.
				//
				printf("%s\n", output_format.c_str());
#ifdef HAS_ANALYZER
				delete analyzer;
#endif
				delete inspector;
				return EXIT_SUCCESS;
			}
			else
			{
				output_format = optarg;
			}

			break;
		case 'r':
			infile = optarg;
			break;
		case 's':
			snaplen = atoi(optarg);
			break;
		case 'q':
			quiet = true;
			break;
		case 'w':
			outfile = optarg;
//				quiet = true;
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
#ifdef HAS_FILTERING
		string filter;

		for(int32_t j = optind; j < argc; j++)
		{
			filter += argv[j];
			if(j < argc)
			{
				filter += " ";
			}
		}

		if(is_filter_display)
		{
			display_filter = new sinsp_filter(inspector, filter);
		}
		else
		{
			inspector->set_filter(filter);
		}
#else
		fprintf(stderr, "filtering not compiled.\n");
#ifdef HAS_ANALYZER
		delete analyzer;
#endif
		delete inspector;
		return EXIT_FAILURE;				
#endif
	}

	//
	// Set the CRTL+C signal
	//
	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting a signal handler.\n");
#ifdef HAS_ANALYZER
		delete analyzer;
#endif
		delete inspector;
		return EXIT_FAILURE;
	}

	//
	// Launch the inspeciotn
	//
	try
	{
		if(infile != "")
		{
			inspector->open(infile);
		}
		else
		{
			inspector->open("");
		}

		if(snaplen != 0)
		{
			inspector->set_snaplen(snaplen);
		}

		if(outfile != "")
		{
			inspector->start_dump(outfile);
		}

		duration = ((double)clock()) / CLOCKS_PER_SEC;
			
		cinfo = do_inspect(inspector, 
			cnt, 
			quiet, 
			absolute_times,
			output_format,
			display_filter);

		duration = ((double)clock()) / CLOCKS_PER_SEC - duration;
	}
	catch(sinsp_exception e)
	{
		if(emitjson)
		{
			printf("]\n");
		}

		cerr << e.what() << endl;
		res = EXIT_FAILURE;
	}
	catch(...)
	{
		res = EXIT_FAILURE;
	}

	//fprintf(stderr, "Elapsed time: %.3lf, %" PRIu64 " events, %.2lf eps\n",
	//	duration,
	//	cinfo.m_nevts,
	//	(double)cinfo.m_nevts / duration);

	fprintf(stderr, "Capture duration: %" PRIu64 ".%" PRIu64 ", %.2lf eps\n",
		cinfo.m_time / 1000000000,
		cinfo.m_time % 1000000000,
		(double)cinfo.m_nevts * 1000000000 / cinfo.m_time);

	delete inspector;
#ifdef HAS_ANALYZER
	delete analyzer;
#endif

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif

	return res;
}
