#include "kernel/yosys.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"

#include <stdlib.h>

USING_YOSYS_NAMESPACE

PRIVATE_NAMESPACE_BEGIN

#define ID2NAME(id) (id.str().substr(1))
#define NameTaint(id, t_id) (id.str() + "_taint_" + std::to_string(t_id))
#define NameTaint_1_ARGS(id) NameTaint(id, 0)
#define NameTaint_2_ARGS(id, t_id) NameTaint(id, t_id)
#define __NameTaint_GET_3TH_ARG(arg1, arg2, arg3, ...) arg3
#define __NameTaint_MACRO_CHOOSER(...) __NameTaint_GET_3TH_ARG(__VA_ARGS__, NameTaint_2_ARGS, NameTaint_1_ARGS, )
#define ID2NAMETaint(...) __NameTaint_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

struct TCovWorker {
	bool verbose = false;

	void instrument_coverage(RTLIL::Module *module) {
		if (module->get_bool_attribute(ID(pift_ignore_module)))
			return;

		std::vector<RTLIL::Cell*> reg_list;
		for (auto c : module->cells().to_vector()) {
			if (c->type.in(ID(taintcell_dff))) {
				reg_list.push_back(c);
			}
		}

		if (!reg_list.empty()) {
			if (verbose)
					log("module %s with %ld tainted register\n", module->name.c_str(), reg_list.size());

			unsigned int reg_num_width = std::max((unsigned int)(std::log2(reg_list.size()) + 1), 8u);
			unsigned int module_hash_width = std::min(reg_num_width, 15u) + 1;
			unsigned int module_hash_state = std::pow(2, module_hash_width) - 1;

			int reg_cnt = 0;
			RTLIL::Cell* first_reg = reg_list.back();
			reg_list.pop_back();
			first_reg->setParam(ID(COVERAGE_WIDTH), module_hash_width);
			first_reg->setParam(ID(COVERAGE_ID), (rand() % module_hash_state) + 1);
			first_reg->setPort(ID(taint_hash), module->addWire(RTLIL::IdString("\\_" + std::to_string(reg_cnt++) + "_taint_covHash"), module_hash_width));
			RTLIL::SigSpec cov_hash = first_reg->getPort(ID(taint_hash));

			for (auto next_reg : reg_list) {
				next_reg->setParam(ID(COVERAGE_WIDTH), module_hash_width);
				next_reg->setParam(ID(COVERAGE_ID), (rand() % module_hash_state) + 1);
				next_reg->setPort(ID(taint_hash), module->addWire(RTLIL::IdString("\\_" + std::to_string(reg_cnt++) + "_taint_covHash"), module_hash_width));
				cov_hash = module->Xor(NEW_ID, cov_hash, next_reg->getPort(ID(taint_hash)));
			}

			RTLIL::Cell* cov_collect = module->addCell(NEW_ID, ID(tainthelp_coverage));
			cov_collect->setParam(ID(COVERAGE_WIDTH), module_hash_width);
			cov_collect->setPort(ID(COV_HASH), cov_hash);
			cov_collect->set_bool_attribute(ID(keep), true);
		}
	}
};


struct TaintCoveragePass : public Pass {
	TaintCoveragePass() : Pass("tcov") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override {
		log_header(design, "Executing Taint Coverage Instrumentation Pass \n");
		TCovWorker worker;
		size_t argidx;
		unsigned int seed = time(NULL);
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
			if (args[argidx] == "--seed") {
				seed = atoi(args[++argidx].c_str());
				continue;
			}
		}
		extra_args(args, argidx, design);

		srand(seed);
		if (worker.verbose)
			log("Instrumentation with seed: %u\n", seed);

		for (RTLIL::Module *module : design->modules()) {
			if (worker.verbose)
				log("instrument module %s @%s\n", module->name.c_str(), module->get_src_attribute().c_str());
			worker.instrument_coverage(module);
		}
	}
} TaintCoveragePass;

PRIVATE_NAMESPACE_END
