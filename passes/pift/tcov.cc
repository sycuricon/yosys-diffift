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
	bool array_only = false;

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

				if (c->get_bool_attribute(ID(pift_taint_sink)))
					sink_cells.push_back(c);
				else if (!array_only)
					taint_cells.push_back(c);
			}
			else if (c->type.in(ID(taintcell_mem))) {
				if (verbose)
					log("catch a tainted memory %s @%s\n", c->name.c_str(), c->get_src_attribute().c_str());
				c->setPort(
					ID(taint_sum),
					module->addWire(RTLIL::IdString("\\_" + std::to_string(cell_cnt++) + "_mem_taint_sum"), c->getParam(ID::ABITS).as_int()));

				if (c->get_bool_attribute(ID(pift_taint_sink)))
					sink_cells.push_back(c);
				else if (!array_only)
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

		RTLIL::SigSpec sink_acc = RTLIL::SigSpec(RTLIL::Const(0, 32));
		for (auto c : sink_cells) {
			sink_acc = module->Add(NEW_ID, sink_acc, c->getPort(ID(taint_sum)));
		}

		RTLIL::Wire *sink_sum = module->addWire(ID(taint_sink_sum), sink_acc.size());
		module->connect(sink_sum, sink_acc);
		sink_sum->set_bool_attribute(ID(keep));

		RTLIL::SigSpec local_acc = RTLIL::SigSpec(RTLIL::Const(0, 32));
		for (auto c : taint_cells) {
			local_acc = module->Add(NEW_ID, local_acc, c->getPort(ID(taint_sum)));
		}

		RTLIL::Wire *local_sum = module->addWire(ID(taint_local_sum), local_acc.size());
		module->connect(local_sum, local_acc);
		local_sum->set_bool_attribute(ID(keep));

		RTLIL::SigSpec hier_acc = RTLIL::SigSpec(RTLIL::Const(0, 32));
		for (auto sm : submodule_cells) {
			hier_acc = module->Add(NEW_ID, hier_acc, sm->getPort(ID(taint_sum)));
		}

		RTLIL::Wire *hier_sum = module->addWire(ID(taint_hier_sum), hier_acc.size());
		module->connect(hier_sum, hier_acc);

		RTLIL::SigSpec taint_sum = module->Add(NEW_ID, sink_sum, module->Add(NEW_ID, local_sum, hier_sum));
		RTLIL::Wire *taint_sum_port = module->addWire(ID(taint_sum), 32);
		taint_sum_port->port_input = false;
		taint_sum_port->port_output = true;

		module->connect(taint_sum_port, taint_sum);

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
			if (args[argidx] == "--array_only") {
				worker.array_only = true;
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
