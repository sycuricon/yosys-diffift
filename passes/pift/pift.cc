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

#define NO_STYLE	"\033[0m"
#define RED			"\033[31m"
#define GREEN		"\033[32m"
#define YELLOW		"\033[33m"
#define BLUE		"\033[34m"
#define PURPLE		"\033[35m"
#define CYAN		"\033[36m"
#define GREY		"\033[90m"
#define PINK		"\033[95m"


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
	std::vector<std::string> ignore_ports;
	dict<std::string, pool<std::string>> vlist;

	void addTaintCell_1I1O(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_2I1O(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_mux(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_dff(RTLIL::Module *module, RTLIL::Cell *origin);
	void addTaintCell_mem(RTLIL::Module *module, RTLIL::Cell *origin);

	RTLIL::SigSpec get_port(RTLIL::Cell *cell, RTLIL::IdString &port_name) {
		if (cell->hasPort(port_name))
			return cell->getPort(port_name);
		else
			return RTLIL::SigSpec(RTLIL::Const(0));
	}

	std::vector<RTLIL::SigSpec> get_taint_signals(RTLIL::Module *module, const RTLIL::SigSpec &sig) {
		std::vector<RTLIL::SigSpec> sig_t(taint_num);

		if (verbose) {
			log("\t\tgenerate taint signal for " GREEN "%s" NO_STYLE " %s%s%s \n", 
				log_signal(sig, false),
				sig.is_wire() ? "wire " : "",
				sig.is_chunk() ? "chunk " : "",
				sig.is_fully_const() ? "const" : "");
		}

		for (unsigned int taint_id = 0; taint_id < taint_num; taint_id++) {
			for (auto &s: sig.chunks()) {
				if (s.is_wire() && 
					!in_list(ID2NAME(s.wire->name), ignore_ports) && 
					!s.wire->get_bool_attribute(ID(pift_taint_wire))) {
					RTLIL::Wire *w = module->wire(ID2NAMETaint(s.wire->name, taint_id));
					if (verbose)
						log(GREEN "\t\t\t(%s) %s " GREY "@%s" NO_STYLE "\n", 
						w == nullptr ? "new" : "exist",
						log_signal(s, false), s.wire->get_src_attribute().c_str());
					if (w == nullptr) {
						w = module->addWire(ID2NAMETaint(s.wire->name, taint_id), s.wire);
						w->port_input = false;
						w->port_output = false;
						w->set_bool_attribute(ID(pift_taint_wire), true);
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
		if (module->get_bool_attribute(ID(pift_port_instrumented)) ||
			module->get_bool_attribute(ID(pift_ignore_module))) {
				module->set_bool_attribute(ID(pift_port_instrumented), true);
				return;
		}

		size_t port_count = 0;
		for (auto w : module->wires().to_vector()) {
			if ((w->port_input || w->port_output) && 
			    !in_list(ID2NAME(w->name), ignore_ports) &&
				!w->get_bool_attribute(ID(pift_taint_wire))) {
				if (verbose)
					log(YELLOW "\t(p:%ld) " NO_STYLE "instrument %s " YELLOW "port" NO_STYLE ": " BLUE "%s " GREY "@%s" NO_STYLE "\n", 
						port_count++,
						w->port_input ? w->port_output ? "inout" : "input" : "output",
						w->name.c_str(),
						w->get_src_attribute().c_str()
					);

				std::vector<RTLIL::SigSpec> port_taint = get_taint_signals(module, w);

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					if (module->get_bool_attribute(ID(pift_keep_pin))) {
						if (w->port_input)
							module->connect(port_taint[taint_id], RTLIL::SigSpec(RTLIL::Const(0, w->width)));
					}
					else {
						port_taint[taint_id].as_wire()->port_input = w->port_input;
						port_taint[taint_id].as_wire()->port_output = w->port_output;
					}
				}
			}
		}
		module->fixup_ports();
		module->set_bool_attribute(ID(pift_port_instrumented), true);
	}

	void instrument_cell(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_cell_instrumented)) ||
			module->get_bool_attribute(ID(pift_ignore_module))) {
				module->set_bool_attribute(ID(pift_cell_instrumented), true);
				return;
		}

		size_t cell_count = 0;
		for (auto c : module->cells().to_vector()) {
			if (verbose)
				log(CYAN "\t[c:%ld] " NO_STYLE "instrument " CYAN "cell" BLUE " %s" NO_STYLE " instance " GREEN "%s " GREY "@%s" NO_STYLE "\n", 
					cell_count++, 
					c->type.c_str(), 
					c->name.c_str(), 
					c->get_src_attribute().c_str()
				);
			
			if (c->type.in(
			    ID($not), ID($pos), ID($neg),
			    ID($reduce_and), ID($reduce_or), ID($reduce_xor), ID($reduce_xnor), ID($reduce_bool),
			    ID($logic_not)
			))
				addTaintCell_1I1O(module, c);
			else if (c->type.in(
				   ID($and), ID($or), ID($xor), ID($xnor),
				   ID($lt), ID($le), ID($eq), ID($ne), ID($ge), ID($gt),
				   ID($add), ID($sub), ID($mul), ID($div), ID($mod), ID($divfloor), ID($modfloor),
				   ID($logic_and), ID($logic_or),
				   ID($shl), ID($shr), ID($sshl), ID($sshr), ID($shift), ID($shiftx)
			))
				addTaintCell_2I1O(module, c);
			else if (c->type.in(
				ID($mux)
			))
				addTaintCell_mux(module, c);

			else if (c->type.in(
				ID($dff), ID($sdff), ID($adff), 
				ID($dffe), ID($sdffe), ID($adffe), 
				ID($sdffce)
			))
				addTaintCell_dff(module, c);

			else if (c->type.in(
				ID($mem_v2)
			))
				addTaintCell_mem(module, c);

			else if (module->design->module(c->type) != nullptr) {
				RTLIL::Module *cell_module = module->design->module(c->type);

				bool ignore_module = cell_module->get_bool_attribute(ID(pift_ignore_module));

				for (auto &it : dict<RTLIL::IdString, RTLIL::SigSpec> {c->connections()}) {
					bool ignore_port = in_list(ID2NAME(it.first), ignore_ports);
					if (verbose)
						log("\t\tinst port " BLUE "%s " GREEN "%s" NO_STYLE "\n", it.first.c_str(), log_signal(it.second, false));

					std::vector<RTLIL::SigSpec> port_taint = get_taint_signals(module, it.second);
					for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
						if (ignore_module || ignore_port) {
							if (cell_module->wire(it.first)->port_input)
								break;
							else if (cell_module->wire(it.first)->port_output)
								module->connect(port_taint[taint_id], RTLIL::SigSpec(RTLIL::Const(0, it.second.size())));
							else
								log_cmd_error("Catch an unsupported port: %s!\n", ID2NAME(it.first).c_str());
						}
						else {
							if (!port_taint[taint_id].is_fully_const() || cell_module->wire(it.first)->port_input)
								c->setPort(ID2NAMETaint(it.first, taint_id), port_taint[taint_id]);	
						}
					}
				}
			}
			else
				log_cmd_error("Catch an unsupported cell: %s!\n", c->type.c_str());
		}

		module->set_bool_attribute(ID(pift_cell_instrumented), true);
	}

	void instrument_wire(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_wire_instrumented)) ||
			module->get_bool_attribute(ID(pift_ignore_module))) {
				module->set_bool_attribute(ID(pift_wire_instrumented), true);
				return;
		}

		size_t wire_count = 0;
		for (auto &conn : std::vector<RTLIL::SigSig> {module->connections()}) {
			if (verbose)
				log(PINK "\t-w:%ld- " NO_STYLE "instrument " PINK "connection" NO_STYLE " from " GREEN "%s" NO_STYLE " to " GREEN "%s" NO_STYLE "\n", 
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
		instrument_wire(module);
		instrument_cell(module);
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
		RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_1I1O));
		cell->parameters = origin->parameters;
		cell->setParam(ID(TYPE), ID2NAME(origin->type));
		cell->set_src_attribute(origin->get_src_attribute());
		cell->set_bool_attribute(ID(pift_taint_gate), true);

		cell->setPort(ID::A, port[A]);
		// cell->setPort(ID::Y, port[Y]);

		cell->setPort(ID(A_taint), port_taint[A][taint_id]);
		cell->setPort(ID(Y_taint), port_taint[Y][taint_id]);
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

		cell->setPort(ID(A_taint), port_taint[A][taint_id]);
		cell->setPort(ID(B_taint), port_taint[B][taint_id]);
		cell->setPort(ID(Y_taint), port_taint[Y][taint_id]);
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
		// cell->setPort(ID::Y, port[Y]);

		cell->setPort(ID(A_taint), port_taint[A][taint_id]);
		cell->setPort(ID(B_taint), port_taint[B][taint_id]);
		cell->setPort(ID(S_taint), port_taint[S][taint_id]);
		cell->setPort(ID(Y_taint), port_taint[Y][taint_id]);
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

		if (module->name.isPublic() && (port[Q].is_wire() && port[Q].as_wire()->name.isPublic())) {
			if (vlist[ID2NAME(module->name)].count(ID2NAME(port[Q].as_wire()->name)) > 0) {
				cell->set_bool_attribute(ID(pift_taint_sink), true);
			}
		}

		cell->setPort(ID::CLK, port[CLK]);
		cell->setPort(ID::SRST, port[SRST]);
		cell->setPort(ID::ARST, port[ARST]);
		cell->setPort(ID::EN, port[EN]);
		cell->setPort(ID::D, port[D]);
		cell->setPort(ID::Q, port[Q]);
		cell->setPort(ID(SRST_taint), port_taint[SRST][taint_id]);
		cell->setPort(ID(ARST_taint), port_taint[ARST][taint_id]);
		cell->setPort(ID(EN_taint), port_taint[EN][taint_id]);
		cell->setPort(ID(D_taint), port_taint[D][taint_id]);
		cell->setPort(ID(Q_taint), port_taint[Q][taint_id]);

		if (port[Q].is_wire() && port[Q].as_wire()->has_attribute(ID(divaift_liveness_mask))) {
			std::string liveness_attr = port[Q].as_wire()->get_string_attribute(ID(divaift_liveness_mask));
			std::vector<std::string> liveness_args;
			split_by(liveness_attr, ",", liveness_args);
			log("liveness_args: %ld, %s\n", liveness_args.size(), liveness_attr.c_str());
			cell->setParam(ID(LIVENESS_TYPE), liveness_args[0]);

			if (liveness_args[0] == "queue") {
				// type, size, idx, enq, deq, full
				if (liveness_args.size() != 6)
					log_cmd_error("Invalid queue arguements: %s\n", liveness_attr.c_str());

				RTLIL::Wire* queue_enq = module->wire(RTLIL::escape_id(liveness_args[3]));
				RTLIL::Wire* queue_deq = module->wire(RTLIL::escape_id(liveness_args[4]));
				RTLIL::Wire* queue_full = module->wire(RTLIL::escape_id(liveness_args[5]));

				if (queue_enq == nullptr || queue_deq == nullptr || queue_full == nullptr)
					log_cmd_error("Invalid queue ptr: %s %s %s\n", 
						liveness_args[3].c_str(), 
						liveness_args[4].c_str(),
						liveness_args[5].c_str());

				cell->setPort(ID(LIVENESS_OP0), queue_enq);
				cell->setPort(ID(LIVENESS_OP1), queue_deq);
				cell->setPort(ID(LIVENESS_OP2), queue_full);
				cell->setParam(ID(LIVENESS_SIZE), std::stoi(liveness_args[1]));
				cell->setParam(ID(LIVENESS_IDX), std::stoi(liveness_args[2]));
			}
			else if (liveness_args[0] == "bitmap" || liveness_args[0] == "bitmap_n") {
				// type, size, idx, vector
				if (liveness_args.size() != 4)
					log_cmd_error("Invalid bitmap arguements: %s\n", liveness_attr.c_str());
				
				RTLIL::Wire* bitmap_vector = module->wire(RTLIL::escape_id(liveness_args[3]));

				if (bitmap_vector == nullptr)
					log_cmd_error("Invalid bitmap vector: %s\n", liveness_args[3].c_str());

				cell->setPort(ID(LIVENESS_OP0), bitmap_vector);
				cell->setParam(ID(LIVENESS_SIZE), std::stoi(liveness_args[1]));
				cell->setParam(ID(LIVENESS_IDX), std::stoi(liveness_args[2]));
			}
		}
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
		cell->unsetParam(ID::INIT);
		cell->unsetParam(ID::RD_INIT_VALUE);
		cell->unsetParam(ID::RD_WIDE_CONTINUATION);
		cell->set_src_attribute(origin->get_src_attribute());
		cell->set_bool_attribute(ID(pift_taint_mem), true);

		cell->set_bool_attribute(ID(pift_taint_sink), true);

		cell->setPort(ID::RD_CLK, port[RD_CLK]);
		cell->setPort(ID::RD_EN, port[RD_EN]);
		cell->setPort(ID::RD_ARST, port[RD_ARST]);
		cell->setPort(ID::RD_SRST, port[RD_SRST]);
		cell->setPort(ID::RD_ADDR, port[RD_ADDR]);
		// cell->setPort(ID::RD_DATA, port[RD_DATA]);
		cell->setPort(ID::WR_CLK, port[WR_CLK]);
		cell->setPort(ID::WR_EN, port[WR_EN]);
		cell->setPort(ID::WR_ADDR, port[WR_ADDR]);
		// cell->setPort(ID::WR_DATA, port[WR_DATA]);
		
		cell->setPort(ID(RD_EN_taint), port_taint[RD_EN][taint_id]);
		cell->setPort(ID(RD_ARST_taint), port_taint[RD_ARST][taint_id]);
		cell->setPort(ID(RD_SRST_taint), port_taint[RD_SRST][taint_id]);
		cell->setPort(ID(RD_ADDR_taint), port_taint[RD_ADDR][taint_id]);
		cell->setPort(ID(RD_DATA_taint), port_taint[RD_DATA][taint_id]);
		cell->setPort(ID(WR_EN_taint), port_taint[WR_EN][taint_id]);
		cell->setPort(ID(WR_ADDR_taint), port_taint[WR_ADDR][taint_id]);
		cell->setPort(ID(WR_DATA_taint), port_taint[WR_DATA][taint_id]);

		if (origin->has_attribute(ID(divaift_liveness_mask))) {
			std::string liveness_attr = origin->get_string_attribute(ID(divaift_liveness_mask));
			std::vector<std::string> liveness_args;
			split_by(liveness_attr, ",", liveness_args);
			log("liveness_args: %ld, %s\n", liveness_args.size(), liveness_attr.c_str());
			cell->setParam(ID(LIVENESS_TYPE), liveness_args[0]);

			if (liveness_args[0] == "queue") {
				// type, enq, deq, full
				if (liveness_args.size() != 4)
					log_cmd_error("Invalid queue arguements: %s\n", liveness_attr.c_str());

				RTLIL::Wire* queue_enq = module->wire(RTLIL::escape_id(liveness_args[1]));
				RTLIL::Wire* queue_deq = module->wire(RTLIL::escape_id(liveness_args[2]));
				RTLIL::Wire* queue_full = module->wire(RTLIL::escape_id(liveness_args[3]));

				if (queue_enq == nullptr || queue_deq == nullptr)
					log_cmd_error("Invalid queue ptr: %s %s %s\n", 
						liveness_args[1].c_str(), 
						liveness_args[2].c_str(),
						liveness_args[3].c_str());

				cell->setPort(ID(LIVENESS_OP0), queue_enq);
				cell->setPort(ID(LIVENESS_OP1), queue_deq);
				cell->setPort(ID(LIVENESS_OP2), queue_full);
			}
			else if (liveness_args[0] == "bitmap" || liveness_args[0] == "bitmap_n") {
				// type, vector
				if (liveness_args.size() != 2)
					log_cmd_error("Invalid bitmap arguements: %s\n", liveness_attr.c_str());
				
				RTLIL::Wire* bitmap_vector = module->wire(RTLIL::escape_id(liveness_args[1]));

				if (bitmap_vector == nullptr)
					log_cmd_error("Invalid bitmap vector: %s\n", liveness_args[1].c_str());

				cell->setPort(ID(LIVENESS_OP0), bitmap_vector);
			}
		}
		else if (module->name.begins_with(RTLIL::escape_id("Queue").c_str()) || module->name.begins_with(RTLIL::escape_id("Queue").c_str())) {
			if (cell->getParam(ID(SIZE)).as_int() == 1) {
				cell->setParam(ID(LIVENESS_TYPE), Yosys::RTLIL::Const("cond"));
				RTLIL::Wire* full = module->wire(RTLIL::escape_id("maybe_full"));

				if (full == nullptr)
					log_cmd_error("Invalid queue ptr: %s\n", "maybe_full");

				cell->setPort(ID(LIVENESS_OP0), full);
			}
			else {
				cell->setParam(ID(LIVENESS_TYPE), Yosys::RTLIL::Const("queue"));
				RTLIL::Wire* queue_enq = module->wire(RTLIL::escape_id("enq_ptr_value"));
				RTLIL::Wire* queue_deq = module->wire(RTLIL::escape_id("deq_ptr_value"));
				RTLIL::Wire* queue_full = module->wire(RTLIL::escape_id("maybe_full"));

				if (queue_enq == nullptr || queue_deq == nullptr || queue_full == nullptr)
					log_cmd_error("Invalid queue ptr: enq_ptr_value deq_ptr_value maybe_full\n");

				cell->setPort(ID(LIVENESS_OP0), queue_enq);
				cell->setPort(ID(LIVENESS_OP1), queue_deq);
				cell->setPort(ID(LIVENESS_OP2), queue_full);
			}
		}
	}
}


struct ProgrammableIFTPass : public Pass {
	ProgrammableIFTPass() : Pass("pift") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override {
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
			if (args[argidx] == "--vec_anno") {
				std::string anno = args[++argidx];
				std::ifstream anno_file(anno);
				if (!anno_file.is_open())
					log_cmd_error("Cannot open file %s\n", anno.c_str());
				
				std::string current_module;
				std::string line;
				while (std::getline(anno_file, line)) {
					line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

					if (line.empty() || line[0] == '#')
						continue;
					
					if (line[0] == '@') {
						std::string reg_name = line.substr(1);
						worker.vlist[current_module].insert(reg_name);
					}
					else {
						current_module = line;
					}
				}
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

		size_t module_count = 0;
		for (RTLIL::Module *module : design->modules()) {
			if (worker.verbose)
				log(PURPLE "{m:%ld} " NO_STYLE "instrument " PURPLE "module" BLUE " %s " GREY "@%s" NO_STYLE "\n", 
					module_count++, 
					module->name.c_str(), 
					module->get_src_attribute().c_str());
			worker.instrument(module);
		}
	}
} ProgrammableIFTPass;

PRIVATE_NAMESPACE_END
