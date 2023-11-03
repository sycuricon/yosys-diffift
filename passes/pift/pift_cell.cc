#include "kernel/yosys.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"

USING_YOSYS_NAMESPACE

RTLIL::Cell *addTaintCell_1I1O(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_y, 
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_y_t, 
	bool is_signed, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_1I1O));
	cell->parameters[ID(TYPE)] = type;
	cell->parameters[ID::A_SIGNED] = is_signed;
	cell->parameters[ID::A_WIDTH] = sig_a.size();
	cell->parameters[ID::Y_WIDTH] = sig_y.size();
	cell->setPort(ID::A, sig_a);
	cell->setPort(ID::Y, sig_y);
	cell->setPort(ID(A_t), sig_a_t);
	cell->setPort(ID(Y_t), sig_y_t);
	cell->set_src_attribute(src);
	return cell;
}

RTLIL::Cell *addTaintCell_2I1O(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_y,
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_y_t, 
	bool is_signed, const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_2I1O));
	cell->parameters[ID(TYPE)] = type;
	cell->parameters[ID::A_SIGNED] = is_signed;
	cell->parameters[ID::B_SIGNED] = is_signed;
	cell->parameters[ID::A_WIDTH] = sig_a.size();
	cell->parameters[ID::B_WIDTH] = sig_b.size();
	cell->parameters[ID::Y_WIDTH] = sig_y.size();
	cell->setPort(ID::A, sig_a);
	cell->setPort(ID::B, sig_b);
	cell->setPort(ID::Y, sig_y);
	cell->setPort(ID(A_t), sig_a_t);
	cell->setPort(ID(B_t), sig_b_t);
	cell->setPort(ID(Y_t), sig_y_t);
	cell->set_src_attribute(src);
	return cell;
}

RTLIL::Cell *addTaintCell_mux(
	RTLIL::Module *module, const std::string &type,
	const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_s, const RTLIL::SigSpec &sig_y, 
	const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_s_t, const RTLIL::SigSpec &sig_y_t, 
	const std::string &src) {
	RTLIL::Cell *cell = module->addCell(NEW_ID, ID(taintcell_Mux));
	cell->parameters[ID(TYPE)] = type;
	cell->parameters[ID::WIDTH] = sig_a.size();
	cell->parameters[ID::S_WIDTH] = sig_s.size();
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
