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

struct TCOVWorker {
	bool verbose = false;

	void instrument_coverage(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_ignore_module)))
			return;

		std::vector<RTLIL::Cell*> taint_cells;
		for (auto c : module->cells().to_vector()) {
			if (c->type.in(ID(taintcell_dff))) {
				if (verbose)
					log("catch a tainted register %s @%s\n", c->name.c_str(), c->get_src_attribute().c_str());
				c->setPort(ID(taint_sum), module->addWire(NEW_ID, 1));
				taint_cells.push_back(c);
			}
			else if (c->type.in(ID(taintcell_mem))) {
				if (verbose)
					log("catch a tainted memory %s @%s\n", c->name.c_str(), c->get_src_attribute().c_str());
				c->setPort(ID(taint_sum), module->addWire(NEW_ID, c->getParam(ID::ABITS).as_int()));
				taint_cells.push_back(c);
			}
			else if (module->design->module(c->type) != nullptr) {
				RTLIL::Module *cell_module = module->design->module(c->type);

				if (!cell_module->get_bool_attribute(ID(pift_ignore_module)) &&
					cell_module->get_bool_attribute(ID(pift_port_instrumented))) {
					if (verbose)
						log("catch a tainted module %s @%s\n", c->name.c_str(), c->get_src_attribute().c_str());
					c->setPort(ID(taint_sum), module->addWire(NEW_ID, 32));
					taint_cells.push_back(c);
				}
			}
		}

		RTLIL::SigSpec acc = RTLIL::SigSpec(RTLIL::Const(0, 32));
		for (auto c : taint_cells) {
			acc = module->Add(NEW_ID_SUFFIX("taint_acc"), acc, c->getPort(ID(taint_sum)));
		}

		RTLIL::Wire *sum_port = module->addWire(ID(taint_sum), acc.size());
		sum_port->port_input = false;
		sum_port->port_output = true;

		module->connect(sum_port, acc);

		module->fixup_ports();
	}
};


struct TaintCoveragePass : public Pass {
	TaintCoveragePass() : Pass("tcov") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing Taint Coverage Instrumentation Pass \n");
		TCOVWorker worker;
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
		}
		extra_args(args, argidx, design);

		for (RTLIL::Module *module : design->modules()) {
			if (worker.verbose)
				log("instrument module %s @%s\n", module->name.c_str(), module->get_src_attribute().c_str());
			worker.instrument_coverage(module);
		}
	}
} TaintCoveragePass;

PRIVATE_NAMESPACE_END
