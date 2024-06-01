#include "kernel/yosys.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"

USING_YOSYS_NAMESPACE

PRIVATE_NAMESPACE_BEGIN

#define ID2NAME(id) (id.str().substr(1))
#define NameTaint(id, t_id) (id.str() + "_taint_" + std::to_string(t_id))
#define NameTaint_1_ARGS(id) NameTaint(id, 0)
#define NameTaint_2_ARGS(id, t_id) NameTaint(id, t_id)
#define __NameTaint_GET_3TH_ARG(arg1, arg2, arg3, ...) arg3
#define __NameTaint_MACRO_CHOOSER(...) __NameTaint_GET_3TH_ARG(__VA_ARGS__, NameTaint_2_ARGS, NameTaint_1_ARGS, )
#define ID2NAMETaint(...) __NameTaint_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)


struct TSINKWorker {
	bool verbose = false;
	std::vector<std::string> target_module;
	std::ofstream output;

	void process(RTLIL::Module *module, std::string path) {
		bool is_sink_module = false;
		for (RTLIL::Cell *cell: module->cells()) {
			RTLIL::Module *submodule = module->design->module(cell->type);
			if (submodule == nullptr) {
				if (cell->get_bool_attribute(ID(pift_taint_sink))) {
					is_sink_module = true;
				}
			}
			else {
				process(submodule, path + "/" + ID2NAME(cell->name));
			}
		}

		if (is_sink_module) {
			log("Found sink module: %s\n", path.c_str());
			target_module.push_back(path);
		}
	}
};

struct TaintSinkPass : public Pass {
	TaintSinkPass() : Pass("tsink") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Figure out potential taint sinks module \n");
		TSINKWorker worker;

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
			if (args[argidx] == "--output" && argidx+1 < args.size()) {
				std::string output_file = args[++argidx];
				worker.output.open(output_file);
				if (!worker.output.is_open())
					log_cmd_error("Cannot open file %s\n", output_file.c_str());
				continue;
			}
		}
		extra_args(args, argidx, design);

		worker.process(design->top_module(), "/ldut");

		for (std::string instance: worker.target_module) {
			if (instance.find("tile_reset_domain") == std::string::npos)
				continue;
			worker.output << "fuSetSignal {/Testbench/testHarness" + instance + "/taint_local_sum}" << std::endl;
			worker.output << "fuSetSignal {/Testbench/testHarness_variant" + instance + "/taint_local_sum}" << std::endl;
		}
		worker.output.close();
	}
} TaintSinkPass;

PRIVATE_NAMESPACE_END
