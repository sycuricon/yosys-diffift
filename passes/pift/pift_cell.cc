#include "kernel/yosys.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"

YOSYS_NAMESPACE_BEGIN

#define DEF_TAINT_METHOD(_func, _y_size, _type) 			\
	RTLIL::Cell* add ## _func ## Taint(            			\
	  RTLIL::Module* module,                       			\
	  const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_y, 	\
	  const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_y_t, \
	  bool is_signed, const std::string &src          		\
 	) { 								\
		RTLIL::Cell *cell = module->addCell(NEW_ID, _type); 	\
                cell->parameters[ID(Type)] = std::string(#_func);   	\
		cell->parameters[ID::A_SIGNED] = is_signed;         	\
		cell->parameters[ID::A_WIDTH] = sig_a.size();       	\
		cell->parameters[ID::Y_WIDTH] = sig_y.size();       	\
		cell->setPort(ID::A, sig_a);                        	\
		cell->setPort(ID::Y, sig_y);        		    	\
                cell->setPort(ID(A_t), sig_a_t);                    	\
		cell->setPort(ID(Y_t), sig_y_t);                    	\
		cell->set_src_attribute(src);                       	\
		return cell;                                        	\
	}

DEF_TAINT_METHOD(Not,		sig_a.size(),	ID(tcell_1I1O))
DEF_TAINT_METHOD(Pos,		sig_a.size(),	ID(tcell_1I1O))
DEF_TAINT_METHOD(Neg,		sig_a.size(),	ID(tcell_1I1O))
DEF_TAINT_METHOD(ReduceAnd,	1,		ID(tcell_1I1O))
DEF_TAINT_METHOD(ReduceOr,	1,		ID(tcell_1I1O))
DEF_TAINT_METHOD(ReduceXor,	1,		ID(tcell_1I1O))
DEF_TAINT_METHOD(ReduceXnor,	1,		ID(tcell_1I1O))
DEF_TAINT_METHOD(ReduceBool,	1,		ID(tcell_1I1O))
DEF_TAINT_METHOD(LogicNot,	1,		ID(tcell_1I1O))
#undef DEF_TAINT_METHOD

#define DEF_TAINT_METHOD(_func, _y_size, _type) 							\
	RTLIL::Cell* add ## _func ## Taint(            							\
	  RTLIL::Module* module,                       							\
	  const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_y, 	\
	  const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_y_t, 	\
	  bool is_signed, const std::string &src       							\
 	) { 												\
		RTLIL::Cell *cell = module->addCell(NEW_ID, _type); \
                cell->parameters[ID(Type)] = std::string(#_func);   \
		cell->parameters[ID::A_SIGNED] = is_signed;         \
		cell->parameters[ID::B_SIGNED] = is_signed;         \
		cell->parameters[ID::A_WIDTH] = sig_a.size();       \
		cell->parameters[ID::B_WIDTH] = sig_b.size();       \
		cell->parameters[ID::Y_WIDTH] = sig_y.size();       \
		cell->setPort(ID::A, sig_a);                        \
		cell->setPort(ID::B, sig_b);                        \
		cell->setPort(ID::Y, sig_y);                        \
		cell->setPort(ID(A_t), sig_a_t);                    \
		cell->setPort(ID(B_t), sig_b_t);                    \
		cell->setPort(ID(Y_t), sig_y_t);                    \
		cell->set_src_attribute(src);                       \
		return cell;                                        \
	}

DEF_TAINT_METHOD(And,		max(sig_a.size(), sig_b.size()),	ID(tcell_2I1O))
DEF_TAINT_METHOD(Or,		max(sig_a.size(), sig_b.size()),	ID(tcell_2I1O))
DEF_TAINT_METHOD(Xor,		max(sig_a.size(), sig_b.size()),	ID(tcell_2I1O))
DEF_TAINT_METHOD(Xnor,		max(sig_a.size(), sig_b.size()),	ID(tcell_2I1O))
DEF_TAINT_METHOD(Shift,		sig_a.size(), 				ID(tcell_2I1O))
DEF_TAINT_METHOD(Shiftx,	sig_a.size(), 				ID(tcell_2I1O))
DEF_TAINT_METHOD(Lt,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Le,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Eq,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Ne,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Eqx,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Nex,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Ge,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Gt,		1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Add,		max(sig_a.size(), sig_b.size()), 	ID(tcell_2I1O))
DEF_TAINT_METHOD(Sub,		max(sig_a.size(), sig_b.size()), 	ID(tcell_2I1O))
DEF_TAINT_METHOD(Mul,		max(sig_a.size(), sig_b.size()), 	ID(tcell_2I1O))
DEF_TAINT_METHOD(Div,		max(sig_a.size(), sig_b.size()), 	ID(tcell_2I1O))
DEF_TAINT_METHOD(Mod,		max(sig_a.size(), sig_b.size()), 	ID(tcell_2I1O))
DEF_TAINT_METHOD(DivFloor,	max(sig_a.size(), sig_b.size()), 	ID(tcell_2I1O))
DEF_TAINT_METHOD(ModFloor,	max(sig_a.size(), sig_b.size()), 	ID(tcell_2I1O))
DEF_TAINT_METHOD(LogicAnd,	1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(LogicOr,	1, 					ID(tcell_2I1O))
DEF_TAINT_METHOD(Shl,      	sig_a.size(), 				ID(tcell_2I1O))
DEF_TAINT_METHOD(Shr,      	sig_a.size(), 				ID(tcell_2I1O))
DEF_TAINT_METHOD(Sshl,     	sig_a.size(), 				ID(tcell_2I1O))
DEF_TAINT_METHOD(Sshr,     	sig_a.size(), 				ID(tcell_2I1O))
#undef DEF_TAINT_METHOD

#define DEF_TAINT_METHOD(_func, _type, _pmux)												\
	RTLIL::Cell* add ## _func ## Taint(												\
	  RTLIL::Module* module,													\
	  const RTLIL::SigSpec &sig_a, const RTLIL::SigSpec &sig_b, const RTLIL::SigSpec &sig_s, const RTLIL::SigSpec &sig_y,		\
	  const RTLIL::SigSpec &sig_a_t, const RTLIL::SigSpec &sig_b_t, const RTLIL::SigSpec &sig_s_t, const RTLIL::SigSpec &sig_y_t,	\
	  const std::string &src													\
 	) {																\
		RTLIL::Cell *cell = module->addCell(NEW_ID, _type);       \
		cell->parameters[ID(Type)] = std::string(#_func);         \
		cell->parameters[ID::WIDTH] = sig_a.size();               \
		if (_pmux) cell->parameters[ID::S_WIDTH] = sig_s.size();  \
		cell->setPort(ID::A, sig_a);                              \
		cell->setPort(ID::B, sig_b);                              \
		cell->setPort(ID::S, sig_s);                              \
		cell->setPort(ID::Y, sig_y);                              \
		cell->setPort(ID(A_t), sig_a_t);                          \
		cell->setPort(ID(B_t), sig_b_t);                          \
		cell->setPort(ID(S_t), sig_s_t);                          \
		cell->setPort(ID(Y_t), sig_y_t);                          \
		cell->set_src_attribute(src);                             \
		return cell;                                              \
	}

DEF_TAINT_METHOD(Mux,	ID(tcell_MUX),	0)
DEF_TAINT_METHOD(Bwmux,	ID(tcell_MUX),	0)
DEF_TAINT_METHOD(Pmux,	ID(tcell_MUX),	1)
#undef DEF_TAINT_METHOD

YOSYS_NAMESPACE_END
