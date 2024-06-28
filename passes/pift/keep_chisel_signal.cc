#include "kernel/yosys.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"

#include "divaift.h"

USING_YOSYS_NAMESPACE

PRIVATE_NAMESPACE_BEGIN

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
