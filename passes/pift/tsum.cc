#include "kernel/yosys.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"

#include "divaift.h"

USING_YOSYS_NAMESPACE

PRIVATE_NAMESPACE_BEGIN

struct TSumWorker {
	bool verbose = false;

	void instrument_coverage(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_ignore_module)))
			return;

		std::vector<RTLIL::Cell*> sink_cells;
		std::vector<RTLIL::Cell*> taint_cells;
		std::vector<RTLIL::Cell*> submodule_cells;
		int cell_cnt = 0;
		for (auto c : module->cells().to_vector()) {
			if (c->type.in(ID(taintcell_dff))) {
				if (verbose)
					log("catch a tainted register %s @%s\n", c->name.c_str(), c->get_src_attribute().c_str());
				c->setPort(
					ID(taint_sum),
					module->addWire(RTLIL::IdString("\\_" + std::to_string(cell_cnt++) + "_dff_taint_sum"), 1));

				taint_cells.push_back(c);
			}
			else if (c->type.in(ID(taintcell_mem))) {
				if (verbose)
					log("catch a tainted memory %s @%s\n", c->name.c_str(), c->get_src_attribute().c_str());
				c->setPort(
					ID(taint_sum),
					module->addWire(RTLIL::IdString("\\_" + std::to_string(cell_cnt++) + "_mem_taint_sum"), c->getParam(ID::ABITS).as_int()));

				taint_cells.push_back(c);
			}
			else if (module->design->module(c->type) != nullptr) {
				RTLIL::Module *cell_module = module->design->module(c->type);

				if (!cell_module->get_bool_attribute(ID(pift_ignore_module)) &&
					cell_module->get_bool_attribute(ID(pift_port_instrumented))) {
					if (verbose)
						log("catch a tainted module %s @%s\n", c->name.c_str(), c->get_src_attribute().c_str());
					c->setPort(
						ID(taint_sum), 
						module->addWire(RTLIL::IdString("\\" + ID2NAME(c->name) + "_" + ID2NAME(cell_module->name) + "_taint_sum"), 32));
					submodule_cells.push_back(c);
				}
			}
		}

		RTLIL::SigSpec local_acc = RTLIL::SigSpec(RTLIL::Const(0, 32));
		for (auto c : taint_cells) {
			local_acc = module->Add(NEW_ID, local_acc, c->getPort(ID(taint_sum)));
		}

		RTLIL::Wire *local_sum = module->addWire(ID(taint_local_sum), local_acc.size());
		module->connect(local_sum, local_acc);

		RTLIL::SigSpec hier_acc = RTLIL::SigSpec(RTLIL::Const(0, 32));
		for (auto sm : submodule_cells) {
			hier_acc = module->Add(NEW_ID, hier_acc, sm->getPort(ID(taint_sum)));
		}

		RTLIL::Wire *hier_sum = module->addWire(ID(taint_hier_sum), hier_acc.size());
		module->connect(hier_sum, hier_acc);

		RTLIL::SigSpec taint_sum = module->Add(NEW_ID, local_sum, hier_sum);
		RTLIL::Wire *taint_sum_port = module->addWire(ID(taint_sum), 32);
		taint_sum_port->port_input = false;
		taint_sum_port->port_output = true;

		module->connect(taint_sum_port, taint_sum);

		module->fixup_ports();
	}
};


struct TaintSummaryPass : public Pass {
	TaintSummaryPass() : Pass("tsum") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing Taint Summary Instrumentation Pass \n");
		TSumWorker worker;
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
} TaintSummaryPass;

PRIVATE_NAMESPACE_END
