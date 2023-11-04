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

const std::string log_signal_type(const RTLIL::SigSpec &sig) {
	std::string s = std::to_string(sig.size());
	if (sig.is_chunk())
		s.append(" is_chunk");
	if (sig.is_bit())
		s.append(" is_bit");
	if (sig.is_wire())
		s.append(" is_wire");
	if (sig.is_fully_const())
		s.append(" is_fully_const");
	if (sig.is_fully_ones())
		s.append(" is_fully_ones");
	if (sig.is_fully_zero())
		s.append(" is_fully_zero");
	if (sig.is_fully_def())
		s.append(" is_fully_def");
	if (sig.is_fully_undef())
		s.append(" is_fully_undef");
	if (sig.is_onehot())
		s.append(" is_onehot");
	
	return s;
}


struct PIFTWorker {
	bool verbose = false;
	unsigned long taint_num = 1;
	std::vector<string> ignore_ports;

	RTLIL::Cell *addTaintCell_1I1O(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_y, 
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_y_t, 
	bool is_signed, const std::string &src);

	RTLIL::Cell *addTaintCell_2I1O(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_y,
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_y_t, 
	bool is_signed, const std::string &src);

	RTLIL::Cell *addTaintCell_mux(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_s, const RTLIL::SigSpec &sig_y, 
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_s_t, const RTLIL::SigSpec &sig_y_t, 
	const std::string &src);

	RTLIL::Cell* addTaintCell_sdff(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_srst, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	RTLIL::Const srst_value, bool clk_polarity, bool srst_polarity, const std::string &src);

	RTLIL::Cell* addTaintCell_sdffe(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_srst, const RTLIL::SigSpec &sig_en, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_en_t, const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	RTLIL::Const srst_value, bool clk_polarity, bool en_polarity, bool srst_polarity, const std::string &src);

	RTLIL::Cell* addTaintCell_dff(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	bool clk_polarity, const std::string &src);

	RTLIL::Cell* addTaintCell_dffe(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_en, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_en_t, const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	bool clk_polarity, bool en_polarity, const std::string &src);

	void addTaintCell_adff(
	RTLIL::Module *module, RTLIL::Cell *origin, 
	const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t);

	void addTaintCell_sdffce(
	RTLIL::Module *module, RTLIL::Cell *origin,
	const RTLIL::SigSpec &sig_en_t, const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t);

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
			log("\t\tsignal %s %s\n", log_signal(sig, false), log_signal_type(sig).c_str());
		
		for (unsigned int taint_id = 0; taint_id < taint_num; taint_id++) {
			for (auto &s: sig.chunks()) {
				if (verbose)
					log("\t\t\tsub-signal %s %s\n", log_signal(s, false), log_signal_type(s).c_str());

				if (s.is_wire() && !in_list(ID2NAME(s.wire->name), ignore_ports)) {
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
			if (w->port_input && !in_list(ID2NAME(w->name), ignore_ports)) {
				if (verbose)
					log("\t(p:%ld) instrument input port: %s\n", port_count++, w->name.c_str());
				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					RTLIL::Wire *w_t = module->addWire(ID2NAMETaint(w->name, taint_id), w->width);
					w_t->port_input = true;
				}
			}
			else if (w->port_output && !in_list(ID2NAME(w->name), ignore_ports)) {
				if (verbose)
					log("\t(p:%ld) instrument output port: %s\n", port_count++, w->name.c_str());
				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					RTLIL::Wire *w_t = module->addWire(ID2NAMETaint(w->name, taint_id), w->width);
					w_t->port_output = true;
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
				log("\t[c:%ld] instrument cell %s@%s from %s\n", cell_count++, c->type.c_str(), c->name.c_str(), c->get_src_attribute().c_str());
			
			// gate
			if (c->type.in(
			      ID($not), ID($pos), ID($neg),
			      ID($reduce_and), ID($reduce_or), ID($reduce_xor), ID($reduce_xnor), ID($reduce_bool),
			      ID($logic_not))) {
				enum PORT_NAME {A, Y, PORT_NUM};
				RTLIL::SigSpec port[PORT_NUM] = {
				  c->getPort(ID::A),
				  c->getPort(ID::Y)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[A]),
				  get_taint_signals(module, port[Y])
				};
				
				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_1I1O(
						module, c->type.str(), 
						port[A], port[Y], 
						port_taint[A][taint_id], port_taint[Y][taint_id], 
						c->getParam(ID::A_SIGNED).as_bool(), c->get_src_attribute());
				}
			}
			else if (c->type.in(
				   ID($and), ID($or), ID($xor), ID($xnor),
				   ID($shift), ID($shiftx),
				   ID($lt), ID($le), ID($eq), ID($ne), ID($eqx), ID($nex), ID($ge), ID($gt),
				   ID($add), ID($sub), ID($mul), ID($div), ID($mod), ID($divfloor), ID($modfloor),
				   ID($logic_and), ID($logic_or),
				   ID($shl), ID($shr), ID($sshl), ID($sshr))) {
				enum PORT_NAME {A, B, Y, PORT_NUM};
				RTLIL::SigSpec port[PORT_NUM] = {
				  c->getPort(ID::A),
				  c->getPort(ID::B),
				  c->getPort(ID::Y)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[A]),
				  get_taint_signals(module, port[B]),
				  get_taint_signals(module, port[Y])
				};

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_2I1O(
						module, c->type.str(), 
						port[A], port[B], port[Y], 
						port_taint[A][taint_id], port_taint[B][taint_id], port_taint[Y][taint_id], 
						c->getParam(ID::A_SIGNED).as_bool() || c->getParam(ID::B_SIGNED).as_bool(), 
						c->get_src_attribute());
				}

			}
			else if (c->type.in(ID($mux), ID($bwmux), ID($pmux))) {
				enum PORT_NAME {A, B, S, Y, PORT_NUM};
				RTLIL::SigSpec port[PORT_NUM] = {
				  c->getPort(ID::A),
				  c->getPort(ID::B),
				  c->getPort(ID::S),
				  c->getPort(ID::Y)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[A]),
				  get_taint_signals(module, port[B]),
				  get_taint_signals(module, port[S]),
				  get_taint_signals(module, port[Y])
				};

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_mux(
						module, c->type.str(), 
						port[A], port[B], port[S], port[Y], 
						port_taint[A][taint_id], port_taint[B][taint_id], port_taint[S][taint_id], port_taint[Y][taint_id], 
						c->get_src_attribute());
				}
			}

			// flip-flop
			else if (c->type.in(ID($sdff))) {
				enum PORT_NAME {CLK, SRST, D, Q, PORT_NUM};
			    RTLIL::SigSpec port[PORT_NUM] = {
					c->getPort(ID::CLK),
					c->getPort(ID::SRST),
					c->getPort(ID::D),
					c->getPort(ID::Q)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[CLK]),
				  get_taint_signals(module, port[SRST]),
				  get_taint_signals(module, port[D]),
				  get_taint_signals(module, port[Q])
				};

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_sdff(
						module, port[CLK], port[SRST], port[D], port[Q],
						port_taint[D][taint_id], port_taint[Q][taint_id],
						c->getParam(ID(SRST_VALUE)), c->getParam(ID(CLK_POLARITY)).as_bool(), c->getParam(ID(SRST_POLARITY)).as_bool(), c->get_src_attribute());
				}
			}
			else if (c->type.in(ID($sdffe))) {
				enum PORT_NAME {CLK, SRST, EN, D, Q, PORT_NUM};
			    RTLIL::SigSpec port[PORT_NUM] = {
					c->getPort(ID::CLK),
					c->getPort(ID::SRST),
					c->getPort(ID::EN),
					c->getPort(ID::D),
					c->getPort(ID::Q)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[CLK]),
				  get_taint_signals(module, port[SRST]),
				  get_taint_signals(module, port[EN]),
				  get_taint_signals(module, port[D]),
				  get_taint_signals(module, port[Q])
				};

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_sdffe(
						module, port[CLK], port[SRST], port[EN], port[D], port[Q],
						port_taint[EN][taint_id], port_taint[D][taint_id], port_taint[Q][taint_id],
						c->getParam(ID(SRST_VALUE)), c->getParam(ID(CLK_POLARITY)).as_bool(), c->getParam(ID(EN_POLARITY)).as_bool(), c->getParam(ID(SRST_POLARITY)).as_bool(), c->get_src_attribute());
				}
			}
			else if (c->type.in(ID($sdffce))) {
				enum PORT_NAME {CLK, SRST, EN, D, Q, PORT_NUM};
			    RTLIL::SigSpec port[PORT_NUM] = {
					c->getPort(ID::CLK),
					c->getPort(ID::SRST),
					c->getPort(ID::EN),
					c->getPort(ID::D),
					c->getPort(ID::Q)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[CLK]),
				  get_taint_signals(module, port[SRST]),
				  get_taint_signals(module, port[EN]),
				  get_taint_signals(module, port[D]),
				  get_taint_signals(module, port[Q])
				};

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_sdffce(
						module, c,
						port_taint[EN][taint_id], port_taint[D][taint_id], port_taint[Q][taint_id]);
				}
			}
			else if (c->type.in(ID($dff))) {
				enum PORT_NAME {CLK, D, Q, PORT_NUM};
			    RTLIL::SigSpec port[PORT_NUM] = {
					c->getPort(ID::CLK),
					c->getPort(ID::D),
					c->getPort(ID::Q)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[CLK]),
				  get_taint_signals(module, port[D]),
				  get_taint_signals(module, port[Q])
				};

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_dff(
						module, port[CLK], port[D], port[Q],
						port_taint[D][taint_id], port_taint[Q][taint_id],
						c->getParam(ID(CLK_POLARITY)).as_bool(), c->get_src_attribute());
				}
			}
			else if (c->type.in(ID($dffe))) {
				enum PORT_NAME {CLK, EN, D, Q, PORT_NUM};
			    RTLIL::SigSpec port[PORT_NUM] = {
					c->getPort(ID::CLK),
					c->getPort(ID::EN),
					c->getPort(ID::D),
					c->getPort(ID::Q)
				};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
				  get_taint_signals(module, port[CLK]),
				  get_taint_signals(module, port[EN]),
				  get_taint_signals(module, port[D]),
				  get_taint_signals(module, port[Q])
				};

				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_dffe(
						module, port[CLK], port[EN], port[D], port[Q],
						port_taint[EN][taint_id], port_taint[D][taint_id], port_taint[Q][taint_id],
						c->getParam(ID(CLK_POLARITY)).as_bool(), c->getParam(ID(EN_POLARITY)).as_bool(), c->get_src_attribute());
				}
			}
			else if (c->type.in(ID($adff))) {
				enum PORT_NAME {CLK, ARST, D, Q, PORT_NUM};
				std::vector<RTLIL::SigSpec> port_taint[PORT_NUM] = {
					get_taint_signals(module, c->getPort(ID::CLK)),
					get_taint_signals(module, c->getPort(ID::ARST)),
					get_taint_signals(module, c->getPort(ID::D)),
					get_taint_signals(module, c->getPort(ID::Q))
				};
				for (unsigned long taint_id = 0; taint_id < taint_num; taint_id++) {
					addTaintCell_adff(module, c, port_taint[D][taint_id], port_taint[Q][taint_id]);
				}
			}
			else if (c->type.in(ID($mem_v2)))
				addTaintCell_mem(module, c);

			// module
			else if (module->design->module(c->type) != nullptr) {
				RTLIL::Module *cell_module_def = module->design->module(c->type);

				instrument_port(cell_module_def);

				for (auto &it : dict<RTLIL::IdString, RTLIL::SigSpec> {c->connections()}) {
					if (in_list(ID2NAME(it.first), ignore_ports))
						continue;

					if (verbose)
						log("\t\tinst port %s %s %s\n", it.first.c_str(), log_signal(it.second, false), log_signal_type(it.second).c_str());

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
				log("\t-w:%ld- instrument wire <%s> to <%s>\n", 
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

RTLIL::Cell * PIFTWorker::addTaintCell_1I1O(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_y, 
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_y_t, 
	bool is_signed, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_1I1O));
	cell->setParam(ID(TYPE), type);
	cell->setParam(ID::A_SIGNED, is_signed);
	cell->setParam(ID::A_WIDTH, sig_a.size());
	cell->setParam(ID::Y_WIDTH, sig_y.size());
	cell->setPort(ID::A, sig_a);
	cell->setPort(ID::Y, sig_y);
	cell->setPort(ID(A_t), sig_a_t);
	cell->setPort(ID(Y_t), sig_y_t);
	cell->set_src_attribute(src);
	return cell;
}

RTLIL::Cell * PIFTWorker::addTaintCell_2I1O(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_y,
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_y_t, 
	bool is_signed, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_2I1O));
	cell->setParam(ID(TYPE), type);
	cell->setParam(ID::A_SIGNED, is_signed);
	cell->setParam(ID::B_SIGNED, is_signed);
	cell->setParam(ID::A_WIDTH, sig_a.size());
	cell->setParam(ID::B_WIDTH, sig_b.size());
	cell->setParam(ID::Y_WIDTH, sig_y.size());
	cell->setPort(ID::A, sig_a);
	cell->setPort(ID::B, sig_b);
	cell->setPort(ID::Y, sig_y);
	cell->setPort(ID(A_t), sig_a_t);
	cell->setPort(ID(B_t), sig_b_t);
	cell->setPort(ID(Y_t), sig_y_t);
	cell->set_src_attribute(src);
	return cell;
}

RTLIL::Cell * PIFTWorker::addTaintCell_mux(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_s, const RTLIL::SigSpec &sig_y, 
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_s_t, const RTLIL::SigSpec &sig_y_t, 
	const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_mux));
	cell->setParam(ID(TYPE), type);
	cell->setParam(ID::WIDTH, sig_a.size());
	cell->setParam(ID::S_WIDTH, sig_s.size());
	cell->setPort(ID::A, sig_a);
	cell->setPort(ID::B, sig_b);
	cell->setPort(ID::S, sig_s);
	cell->setPort(ID::Y, sig_y);
	cell->setPort(ID(A_t), sig_a_t);
	cell->setPort(ID(B_t), sig_b_t);
	cell->setPort(ID(S_t), sig_s_t);
	cell->setPort(ID(Y_t), sig_y_t);
	cell->set_src_attribute(src);
	return cell;
}

RTLIL::Cell* PIFTWorker::addTaintCell_sdff(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_srst, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	RTLIL::Const srst_value, bool clk_polarity, bool srst_polarity, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_sdff));
	cell->setParam(ID::CLK_POLARITY, clk_polarity);
	cell->setParam(ID::SRST_POLARITY, srst_polarity);
	cell->setParam(ID::SRST_VALUE, srst_value);
	cell->setParam(ID::WIDTH, sig_q.size());
	cell->setPort(ID::CLK, sig_clk);
	cell->setPort(ID::SRST, sig_srst);
	cell->setPort(ID::D, sig_d);
	cell->setPort(ID::Q, sig_q);
	cell->setPort(ID(D_t), sig_d_t);
	cell->setPort(ID(Q_t), sig_q_t);
	cell->set_src_attribute(src);
	cell->set_bool_attribute(ID(tainted), true);
	return cell;
}

RTLIL::Cell* PIFTWorker::addTaintCell_sdffe(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_srst, const RTLIL::SigSpec &sig_en, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_en_t, const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	RTLIL::Const srst_value, bool clk_polarity, bool en_polarity, bool srst_polarity, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_sdffe));
	cell->parameters[ID::CLK_POLARITY] = clk_polarity;
	cell->parameters[ID::EN_POLARITY] = en_polarity;
	cell->parameters[ID::SRST_POLARITY] = srst_polarity;
	cell->parameters[ID::SRST_VALUE] = srst_value;
	cell->parameters[ID::WIDTH] = sig_q.size();
	cell->setPort(ID::CLK, sig_clk);
	cell->setPort(ID::SRST, sig_srst);
	cell->setPort(ID::EN, sig_en);
	cell->setPort(ID::D, sig_d);
	cell->setPort(ID::Q, sig_q);
	cell->setPort(ID(EN_t), sig_en_t);
	cell->setPort(ID(D_t), sig_d_t);
	cell->setPort(ID(Q_t), sig_q_t);
	cell->set_src_attribute(src);
	cell->set_bool_attribute(ID(tainted), true);
	return cell;
}

void PIFTWorker::addTaintCell_sdffce(
	RTLIL::Module *module, RTLIL::Cell *origin,
	const RTLIL::SigSpec &sig_en_t, const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_sdffce));
	cell->parameters = origin->parameters;
	cell->setPort(ID::CLK, origin->getPort(ID::CLK));
	cell->setPort(ID::SRST, origin->getPort(ID::SRST));
	cell->setPort(ID::EN, origin->getPort(ID::EN));
	cell->setPort(ID::D, origin->getPort(ID::D));
	cell->setPort(ID::Q, origin->getPort(ID::Q));
	cell->setPort(ID(EN_t), sig_en_t);
	cell->setPort(ID(D_t), sig_d_t);
	cell->setPort(ID(Q_t), sig_q_t);
	cell->set_src_attribute(origin->get_src_attribute());
	cell->set_bool_attribute(ID(tainted), true);
}

void PIFTWorker::addTaintCell_adff(
	RTLIL::Module *module, RTLIL::Cell *origin, 
	const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_adff));
	cell->parameters = origin->parameters;
	cell->setPort(ID::CLK, origin->getPort(ID::CLK));
	cell->setPort(ID::ARST, origin->getPort(ID::ARST));
	cell->setPort(ID::D, origin->getPort(ID::D));
	cell->setPort(ID::Q, origin->getPort(ID::Q));
	cell->setPort(ID(D_t), sig_d_t);
	cell->setPort(ID(Q_t), sig_q_t);
	cell->set_src_attribute(origin->get_src_attribute());
	cell->set_bool_attribute(ID(tainted), true);
}

RTLIL::Cell* PIFTWorker::addTaintCell_dff(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	bool clk_polarity, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_dff));
	cell->setParam(ID::CLK_POLARITY, clk_polarity);
	cell->setParam(ID::WIDTH, sig_q.size());
	cell->setPort(ID::CLK, sig_clk);
	cell->setPort(ID::D, sig_d);
	cell->setPort(ID::Q, sig_q);
	cell->setPort(ID(D_t), sig_d_t);
	cell->setPort(ID(Q_t), sig_q_t);
	cell->set_src_attribute(src);
	cell->set_bool_attribute(ID(tainted), true);
	return cell;
}

RTLIL::Cell* PIFTWorker::addTaintCell_dffe(
	RTLIL::Module *module, 
	const RTLIL::SigSpec &sig_clk, const RTLIL::SigSpec &sig_en, const RTLIL::SigSpec &sig_d, const RTLIL::SigSpec &sig_q,
	const RTLIL::SigSpec &sig_en_t, const RTLIL::SigSpec &sig_d_t, const RTLIL::SigSpec &sig_q_t,
	bool clk_polarity, bool en_polarity, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_dffe));
	cell->setParam(ID::CLK_POLARITY, clk_polarity);
	cell->setParam(ID::EN_POLARITY, en_polarity);
	cell->setParam(ID::WIDTH, sig_q.size());
	cell->setPort(ID::CLK, sig_clk);
	cell->setPort(ID::EN, sig_en);
	cell->setPort(ID::D, sig_d);
	cell->setPort(ID::Q, sig_q);
	cell->setPort(ID(EN_t), sig_en_t);
	cell->setPort(ID(D_t), sig_d_t);
	cell->setPort(ID(Q_t), sig_q_t);
	cell->set_src_attribute(src);
	cell->set_bool_attribute(ID(tainted), true);
	return cell;
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
		cell->set_bool_attribute(ID(tainted), true);

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
