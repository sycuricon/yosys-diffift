#include "kernel/yosys.h"
#include "kernel/sigtools.h"
#include "kernel/celltypes.h"
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

struct CtrlDFFWorker {
	bool verbose;
	RTLIL::Module* current;
	std::vector<RTLIL::Cell*> dff_list;
	pool<RTLIL::Wire*> mux_select_list;
	dict<RTLIL::Wire*, pool<RTLIL::Wire*>> taint_net;

	CtrlDFFWorker(RTLIL::Module *module, bool verbose) : verbose(verbose), current(module) {
		for (auto c : current->cells()) {
			if (c->type.in(ID(taintcell_dff))) {
				dff_list.push_back(c);
			}
			else if (c->type.in(ID(taintcell_mux))) {
				for (auto w : get_wire_list(c->getPort(ID(S_taint)))) {
					mux_select_list.insert(w);
				}

				pool<RTLIL::Wire*> output_list = get_wire_list(c->getPort(ID(Y_taint)));
				for (auto aw : get_wire_list(c->getPort(ID(A_taint)))) {
					for (auto yw : output_list) {
						taint_net[aw].insert(yw);
					}
				}
				for (auto bw : get_wire_list(c->getPort(ID(B_taint)))) {
					for (auto yw : output_list) {
						taint_net[bw].insert(yw);
					}
				}
			}
			else if (c->type.in(ID(taintcell_1I1O))) {
				pool<RTLIL::Wire*> output_list = get_wire_list(c->getPort(ID(Y_taint)));
				for (auto aw : get_wire_list(c->getPort(ID(A_taint)))) {
					for (auto yw : output_list) {
						taint_net[aw].insert(yw);
					}
				}
			}
			else if (c->type.in(ID(taintcell_2I1O))) {
				pool<RTLIL::Wire*> output_list = get_wire_list(c->getPort(ID(Y_taint)));
				for (auto aw : get_wire_list(c->getPort(ID(A_taint)))) {
					for (auto yw : output_list) {
						taint_net[aw].insert(yw);
					}
				}
				for (auto bw : get_wire_list(c->getPort(ID(B_taint)))) {
					for (auto yw : output_list) {
						taint_net[bw].insert(yw);
					}
				}
			}
		}
		// dump_taint_net();
	}

	pool<RTLIL::Wire*> get_wire_list(RTLIL::SigSpec spec) {
		pool<RTLIL::Wire*> result;
		for (auto &chunk: spec.chunks()) {
			if (chunk.is_wire()) {
				result.insert(chunk.wire);
			}
		}
		return result;
	}

	void print_pool(std::string prefix, pool<RTLIL::Wire*> p) {
		log("%s: ", prefix.c_str());
		for (auto w : p) {
			log("%s ", w->name.c_str());
		}
		log("\n");
	}

	void dump_taint_net() {
		for (auto &t : taint_net) {
			log("taint net %s\n", t.first->name.c_str());
			print_pool("\t", t.second);
		}
	}

	pool<RTLIL::Wire*> search_taintnet(pool<RTLIL::Wire*> search_list, pool<RTLIL::Wire*>& visited) {
		pool<RTLIL::Wire*> result;

		for (auto query : search_list) {
			if (visited.count(query) > 0) {
				continue;
			}

			// log("search %s\n", query->name.c_str());
			if (taint_net.count(query) > 0) {
				// print_pool("todo", taint_net[query]);
				// print_pool("visited", visited);
				visited.insert(query);
				for (auto r : search_taintnet(taint_net[query], visited)) {
					result.insert(r);
				}
			}
			else {
				result.insert(query);
			}
		}

		return result;
	}

	void process() {
		if (mux_select_list.size() == 0 or dff_list.size() == 0) {
			if (verbose)
				log("module %s is ignored since it doesn't have any dff/mux\n", current->name.c_str());
			return;
		}
		for (auto &it : current->connections()) {
			std::vector<RTLIL::SigBit> assign_from_bits = it.second.bits();
			std::vector<RTLIL::SigBit> assign_to_bits = it.first.bits();
			for (size_t i = 0; i < assign_from_bits.size(); i++) {
				if (assign_from_bits[i].is_wire() && assign_to_bits[i].is_wire()) {
					taint_net[assign_from_bits[i].wire].insert(assign_to_bits[i].wire);
				}
			}
		}

		for (auto c : dff_list) {
			pool<RTLIL::Wire*> Q_taint = get_wire_list(c->getPort(ID(Q_taint)));

			pool<RTLIL::Wire*> visited;
			pool<RTLIL::Wire*> taint_list = search_taintnet(Q_taint, visited);
			
			unsigned long int mux_sink = 0;
			for (auto t : taint_list) {
				if (mux_select_list.count(t) > 0) {
					mux_sink ++;
				}
			}

			if (mux_sink > 0) {
				if (verbose)
					log("cell %s (%s) is a control register (fanout: %ld/%ld)\n", 
						c->name.c_str(), 
						c->getParam(ID(TYPE)).decode_string().c_str(),
						mux_sink, taint_list.size()
					);
				c->set_bool_attribute(ID(CTRL_REG), true);
			}
		}

		log("module %s has %ld dff and %ld mux\n", current->name.c_str(), dff_list.size(), mux_select_list.size());
	}
};

struct ControlDFFPass : public Pass {
	ControlDFFPass() : Pass("ctrl_dff") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Find leaf dff \n");
		bool verbose = false;

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				verbose = true;
				continue;
			}
		}
		extra_args(args, argidx, design);

		for (RTLIL::Module *module : design->modules()) {
			CtrlDFFWorker worker(module, verbose);
			worker.process();
		}
	}
} ControlDFFPass;

PRIVATE_NAMESPACE_END
