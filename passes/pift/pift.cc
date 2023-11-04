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

void split_by(const std::string &in, const std::string &delimiter, std::vector<string> &out)
{
	size_t port_start = 0, port_end;
	while ((port_end = in.find(delimiter, port_start)) != std::string::npos) {
		out.push_back(in.substr(port_start, port_end - port_start));
		port_start = port_end + delimiter.length();
	}
	out.push_back(in.substr(port_start));
}

bool in_list(const string &target, std::vector<string> &list)
{
	if (target.empty())
		return false;
	return std::find(std::begin(list), std::end(list), target) != std::end(list);
}

struct PIFTWorker {
	bool verbose = false;
	unsigned long taint_num = 1;
	std::vector<string> ignore_ports;

	void addTaintCell_1I1O(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_2I1O(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_mux(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_dff(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_mem(RTLIL::Module *module, RTLIL::Cell *origin);

	RTLIL::SigSpec get_port(RTLIL::Cell *cell, RTLIL::IdString &port_name) {
		if (cell->hasPort(port_name))
			return cell->getPort(port_name);
		else
			return RTLIL::SigSpec(RTLIL::State::Sx, 1);
	}

	std::vector<RTLIL::SigSpec> get_taint_signals(RTLIL::Module *module, const RTLIL::SigSpec &sig) {
		std::vector<RTLIL::SigSpec> sig_t(taint_num);

		if (verbose)
			log("\t\tgenerate taint signal for %s\n", log_signal(sig, false));
		
		for (unsigned int taint_id = 0; taint_id < taint_num; taint_id++) {
			for (auto &s: sig.chunks()) {
				if (s.is_wire() && !in_list(ID2NAME(s.wire->name), ignore_ports)) {
					if (verbose)
						log("\t\t\t%s @%s\n", log_signal(s, false), s.wire->get_src_attribute().c_str());
					RTLIL::Wire *w = module->wire(ID2NAMETaint(s.wire->name, taint_id));
					if (w == nullptr) {
						w = module->addWire(ID2NAMETaint(s.wire->name, taint_id), s.wire);
						w->port_input = false;
						w->port_output = false;
					}
					sig_t[taint_id].append(RTLIL::SigSpec(w, s.offset, s.width));
				}
				else {
					sig_t[taint_id].append(RTLIL::SigSpec(RTLIL::Const(0, s.width)));
				}
			}
		}

		return sig_t;
	}

	void instrument_port(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_port_instrumented)))
			return;

		size_t port_count = 0;
		for (auto w : module->wires().to_vector()) {
			if ((w->port_input || w->port_output) && !in_list(ID2NAME(w->name), ignore_ports)) {
				if (verbose)
					log("\t(p:%ld) instrument %s port: %s @%s\n", 
						port_count++,
						w->port_input ? w->port_output ? "inout" : "input" : "output",
						w->name.c_str(),
						w->get_src_attribute().c_str()
					);
				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					RTLIL::Wire *w_t = module->addWire(ID2NAMETaint(w->name, taint_id), w->width);
					w_t->port_input = w->port_input;
					w_t->port_output = w->port_output;
				}
			}
		}
		module->fixup_ports();
		module->set_bool_attribute(ID(pift_port_instrumented), true);
	}

	void instrument_cell(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_cell_instrumented)))
			return;

		size_t cell_count = 0;
		for (auto c : module->cells().to_vector()) {
			if (verbose)
				log("\t[c:%ld] instrument cell %s instance %s @%s\n", 
					cell_count++, 
					c->type.c_str(), 
					c->name.c_str(), 
					c->get_src_attribute().c_str()
				);
			
			if (c->type.in(
			      ID($not), ID($pos), ID($neg),
			      ID($reduce_and), ID($reduce_or), ID($reduce_xor), ID($reduce_xnor), ID($reduce_bool),
			      ID($logic_not)))
				addTaintCell_1I1O(module, c);
			else if (c->type.in(
				   ID($and), ID($or), ID($xor), ID($xnor),
				   ID($lt), ID($le), ID($eq), ID($ne), ID($eqx), ID($nex), ID($ge), ID($gt),
				   ID($add), ID($sub), ID($mul), ID($div), ID($mod), ID($divfloor), ID($modfloor),
				   ID($logic_and), ID($logic_or),
				   ID($shift), ID($shiftx), ID($shl), ID($shr), ID($sshl), ID($sshr)))
				addTaintCell_2I1O(module, c);
			else if (c->type.in(ID($mux), ID($bwmux), ID($pmux)))
				addTaintCell_mux(module, c);

			else if (c->type.in(
					ID($dff), ID($sdff), ID($adff), 
					ID($dffe), ID($sdffe), ID($adffe), 
					ID($sdffce)))
				addTaintCell_dff(module, c);

			else if (c->type.in(ID($mem_v2)))
				addTaintCell_mem(module, c);

			else if (module->design->module(c->type) != nullptr) {
				RTLIL::Module *cell_module_def = module->design->module(c->type);
				instrument_port(cell_module_def);

				for (auto &it : dict<RTLIL::IdString, RTLIL::SigSpec> {c->connections()}) {
					if (in_list(ID2NAME(it.first), ignore_ports))
						continue;

					if (verbose)
						log("\t\tinst port %s %s\n", it.first.c_str(), log_signal(it.second, false));

					std::vector<RTLIL::SigSpec> port_taint = get_taint_signals(module, it.second);
					for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
						c->setPort(ID2NAMETaint(it.first, taint_id), port_taint[taint_id]);
					}
				}
			}
			else
				log_cmd_error("Catch an unsupported cell: %s!\n", c->type.c_str());
		}

		module->set_bool_attribute(ID(pift_cell_instrumented), true);
	}

	void instrument_wire(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_wire_instrumented)))
			return;
				
		size_t wire_count = 0;
		for (auto &conn : std::vector<RTLIL::SigSig> {module->connections()}) {
			if (verbose)
				log("\t-w:%ld- instrument connection from %s to %s\n", 
					wire_count++, 
					log_signal(conn.first, false), 
					log_signal(conn.second, false)
				);

			std::vector<RTLIL::SigSpec> lvalue = get_taint_signals(module, conn.first);
			std::vector<RTLIL::SigSpec> rvalue = get_taint_signals(module, conn.second);

			for (unsigned int taint_id = 0; taint_id < taint_num; taint_id++) {
				module->connect(lvalue[taint_id], rvalue[taint_id]);
			}	
		}

		module->set_bool_attribute(ID(pift_wire_instrumented), true);
	}

	void instrument(RTLIL::Module *module) {
		instrument_port(module);
		instrument_cell(module);
		instrument_wire(module);
	}
};

void PIFTWorker::addTaintCell_1I1O(RTLIL::Module *module, RTLIL::Cell *origin) {
	enum PORT_NAME {A, Y, PORT_NUM};
	RTLIL::SigSpec port[PORT_NUM] = {
		get_port(origin, ID::A),
		get_port(origin, ID::Y)
	};
	std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
		get_taint_signals(module, port[A]),
		get_taint_signals(module, port[Y])
	};

	for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
		RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_2I1O));
		cell->parameters = origin->parameters;
		cell->setParam(ID(TYPE), ID2NAME(origin->type));
		cell->set_src_attribute(origin->get_src_attribute());
		cell->set_bool_attribute(ID(pift_taint_gate), true);

		cell->setPort(ID::A, port[A]);
		cell->setPort(ID::Y, port[Y]);

		cell->setPort(ID(A_t), port_taint[A][taint_id]);
		cell->setPort(ID(Y_t), port_taint[Y][taint_id]);
	}
}

void PIFTWorker::addTaintCell_2I1O(RTLIL::Module *module, RTLIL::Cell *origin) {
	enum PORT_NAME {A, B, Y, PORT_NUM};
	RTLIL::SigSpec port[PORT_NUM] = {
		get_port(origin, ID::A),
		get_port(origin, ID::B),
		get_port(origin, ID::Y)
	};
	std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
		get_taint_signals(module, port[A]),
		get_taint_signals(module, port[B]),
		get_taint_signals(module, port[Y])
	};

	for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
		RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_2I1O));
		cell->parameters = origin->parameters;
		cell->setParam(ID(TYPE), ID2NAME(origin->type));
		cell->set_src_attribute(origin->get_src_attribute());
		cell->set_bool_attribute(ID(pift_taint_gate), true);

		cell->setPort(ID::A, port[A]);
		cell->setPort(ID::B, port[B]);
		cell->setPort(ID::Y, port[Y]);

		cell->setPort(ID(A_t), port_taint[A][taint_id]);
		cell->setPort(ID(B_t), port_taint[B][taint_id]);
		cell->setPort(ID(Y_t), port_taint[Y][taint_id]);
	}
}

void PIFTWorker::addTaintCell_mux(RTLIL::Module *module, RTLIL::Cell *origin) {
	enum PORT_NAME {A, B, S, Y, PORT_NUM};
	RTLIL::SigSpec port[PORT_NUM] = {
		get_port(origin, ID::A),
		get_port(origin, ID::B),
		get_port(origin, ID::S),
		get_port(origin, ID::Y)
	};
	std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
		get_taint_signals(module, port[A]),
		get_taint_signals(module, port[B]),
		get_taint_signals(module, port[S]),
		get_taint_signals(module, port[Y])
	};

	for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
		RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_mux));
		cell->parameters = origin->parameters;
		cell->setParam(ID(TYPE), ID2NAME(origin->type));
		cell->set_src_attribute(origin->get_src_attribute());
		cell->set_bool_attribute(ID(pift_taint_gate), true);

		cell->setPort(ID::A, port[A]);
		cell->setPort(ID::B, port[B]);
		cell->setPort(ID::S, port[S]);
		cell->setPort(ID::Y, port[Y]);

		cell->setPort(ID(A_t), port_taint[A][taint_id]);
		cell->setPort(ID(B_t), port_taint[B][taint_id]);
		cell->setPort(ID(S_t), port_taint[S][taint_id]);
		cell->setPort(ID(Y_t), port_taint[Y][taint_id]);
	}
}

void PIFTWorker::addTaintCell_dff(RTLIL::Module *module, RTLIL::Cell *origin) {
	enum PORT_NAME {CLK, SRST, ARST, EN, D, Q, PORT_NUM};
	RTLIL::SigSpec port[PORT_NUM] = {
		get_port(origin, ID::CLK),
		get_port(origin, ID::SRST),
		get_port(origin, ID::ARST),
		get_port(origin, ID::EN),
		get_port(origin, ID::D),
		get_port(origin, ID::Q)
	};
	std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
		get_taint_signals(module, port[CLK]),
		get_taint_signals(module, port[SRST]),
		get_taint_signals(module, port[ARST]),
		get_taint_signals(module, port[EN]),
		get_taint_signals(module, port[D]),
		get_taint_signals(module, port[Q])
	};

	for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
		RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_dff));
		cell->parameters = origin->parameters;
		cell->setParam(ID(TYPE), ID2NAME(origin->type));
		cell->set_src_attribute(origin->get_src_attribute());
		cell->set_bool_attribute(ID(pift_taint_reg), true);

		cell->setPort(ID::CLK, port[CLK]);
		cell->setPort(ID::SRST, port[SRST]);
		cell->setPort(ID::ARST, port[ARST]);
		cell->setPort(ID::EN, port[EN]);
		cell->setPort(ID::D, port[D]);
		cell->setPort(ID::Q, port[Q]);
		cell->setPort(ID(EN_t), port_taint[EN][taint_id]);
		cell->setPort(ID(D_t), port_taint[D][taint_id]);
		cell->setPort(ID(Q_t), port_taint[Q][taint_id]);
	}
}

void PIFTWorker::addTaintCell_mem(RTLIL::Module *module, RTLIL::Cell *origin) {
	enum PORT_NAME {
		RD_CLK, RD_EN, RD_ARST, RD_SRST, RD_ADDR, RD_DATA,
		WR_CLK, WR_EN, WR_ADDR, WR_DATA,
		PORT_NUM
	};
	RTLIL::SigSpec port[PORT_NUM] = {
		get_port(origin, ID::RD_CLK),
		get_port(origin, ID::RD_EN),
		get_port(origin, ID::RD_ARST),
		get_port(origin, ID::RD_SRST),
		get_port(origin, ID::RD_ADDR),
		get_port(origin, ID::RD_DATA),
		get_port(origin, ID::WR_CLK),
		get_port(origin, ID::WR_EN),
		get_port(origin, ID::WR_ADDR),
		get_port(origin, ID::WR_DATA)
	};
	std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
		get_taint_signals(module, port[RD_CLK]),
		get_taint_signals(module, port[RD_EN]),
		get_taint_signals(module, port[RD_ARST]),
		get_taint_signals(module, port[RD_SRST]),
		get_taint_signals(module, port[RD_ADDR]),
		get_taint_signals(module, port[RD_DATA]),
		get_taint_signals(module, port[WR_CLK]),
		get_taint_signals(module, port[WR_EN]),
		get_taint_signals(module, port[WR_ADDR]),
		get_taint_signals(module, port[WR_DATA])
	};

	for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
		RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_mem));
		cell->parameters = origin->parameters;
		cell->set_src_attribute(origin->get_src_attribute());
		cell->set_bool_attribute(ID(pift_taint_mem), true);

		cell->setPort(ID::RD_CLK, port[RD_CLK]);
		cell->setPort(ID::RD_EN, port[RD_EN]);
		cell->setPort(ID::RD_ARST, port[RD_ARST]);
		cell->setPort(ID::RD_SRST, port[RD_SRST]);
		cell->setPort(ID::RD_ADDR, port[RD_ADDR]);
		cell->setPort(ID::RD_DATA, port[RD_DATA]);
		cell->setPort(ID::WR_CLK, port[WR_CLK]);
		cell->setPort(ID::WR_EN, port[WR_EN]);
		cell->setPort(ID::WR_ADDR, port[WR_ADDR]);
		cell->setPort(ID::WR_DATA, port[WR_DATA]);
		
		cell->setPort(ID(RD_EN_t), port_taint[RD_EN][taint_id]);
		cell->setPort(ID(RD_ADDR_t), port_taint[RD_ADDR][taint_id]);
		cell->setPort(ID(RD_DATA_t), port_taint[RD_DATA][taint_id]);
		cell->setPort(ID(WR_EN_t), port_taint[WR_EN][taint_id]);
		cell->setPort(ID(WR_ADDR_t), port_taint[WR_ADDR][taint_id]);
		cell->setPort(ID(WR_DATA_t), port_taint[WR_DATA][taint_id]);
	}
}


struct ProgrammableIFTPass : public Pass {
	ProgrammableIFTPass() : Pass("pift") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing Programmable Information Flow Tracking Instrumentation Pass \n");
		PIFTWorker worker;
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
			if (args[argidx] == "--taint-num") {
				worker.taint_num = std::stoul(args[++argidx]);
				continue;
			}
			if (args[argidx] == "--ignore-ports") {
				std::string ignores = args[++argidx];
				split_by(ignores, ",", worker.ignore_ports);
				continue;
			}
		}
		extra_args(args, argidx, design);

		if (worker.verbose) {
			log("[*] Taint Width: %ld\n", worker.taint_num);
			log("[*] Ignored Ports: ");
			for (const auto &p : worker.ignore_ports)
				log("%s ", p.c_str());
			log("\n");
		}

		for (RTLIL::Module *module : design->modules()) {
			log("Instrument module %s\n", module->name.c_str());
			worker.instrument(module);
		}
	}
} ProgrammableIFTPass;

PRIVATE_NAMESPACE_END
