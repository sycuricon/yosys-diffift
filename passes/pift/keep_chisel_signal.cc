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

struct KeepSignalWorker {
	bool verbose = false;

	void add_keep_attr(RTLIL::Module *module) {
		if (module->name.begins_with(RTLIL::escape_id("Queue").c_str()) || module->name.begins_with(RTLIL::escape_id("XS_Queue").c_str())) {
			if (verbose)
				log("Identify chisel queue module %s\n", module->name.c_str());

			RTLIL::Wire* maybe_full = module->wire(RTLIL::escape_id("maybe_full"));
			if (maybe_full != nullptr) {
				maybe_full->set_bool_attribute(ID(keep), true);
				log("maybe_full\n");
			}

			RTLIL::Wire* empty = module->wire(RTLIL::escape_id("empty"));
			if (empty != nullptr) {
				empty->set_bool_attribute(ID(keep), true);
				log("empty\n");
			}

			RTLIL::Wire* enq_ptr_value = module->wire(RTLIL::escape_id("enq_ptr_value"));
			if (enq_ptr_value != nullptr) {
				enq_ptr_value->set_bool_attribute(ID(keep), true);
				log("enq_ptr_value\n");
			}

			RTLIL::Wire* deq_ptr_value = module->wire(RTLIL::escape_id("deq_ptr_value"));
			if (deq_ptr_value != nullptr) {
				deq_ptr_value->set_bool_attribute(ID(keep), true);
				log("deq_ptr_value\n");
			}

			return;
		}
	}
};

struct KeepSignalPass : public Pass {
	KeepSignalPass() : Pass("keep_chisel_signals") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override {
		log_header(design, "Identify chisel built-in signals\n");
		KeepSignalWorker worker;
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
		}
		extra_args(args, argidx, design);

		for (RTLIL::Module *module : design->modules()) {
			worker.add_keep_attr(module);
		}
	}
} KeepSignalPass;

PRIVATE_NAMESPACE_END
