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

RTLIL::Cell *addTaintCell_2I1O(
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

RTLIL::Cell *addTaintCell_mux(
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

RTLIL::Cell* addTaintCell_sdff(
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

RTLIL::Cell* addTaintCell_sdffe(
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

RTLIL::Cell* addTaintCell_dff(
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

RTLIL::Cell* addTaintCell_dffe(
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

