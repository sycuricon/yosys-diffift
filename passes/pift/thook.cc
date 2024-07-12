#include "kernel/yosys.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"

#include "divaift.h"

USING_YOSYS_NAMESPACE

PRIVATE_NAMESPACE_BEGIN

struct THookWorker {
	bool verbose = false;

	void process(RTLIL::Module *module) {
		for (RTLIL::Cell *cell: module->cells()) {
			if (module->get_bool_attribute(ID(pift_ignore_module)) || !cell->type.isPublic())
				continue;
			
			cell->setParam(ID(IFT_RULE), std::string("REPLACE_ME_TO_IFT_RULE"));
		}
	}
};

struct TainthookPass : public Pass {
	TainthookPass() : Pass("thook") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "IFT_RULE parameter hook instrumentation\n");
		THookWorker worker;

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
		}
		extra_args(args, argidx, design);

		for (auto module : design->modules()) {
			worker.process(module);
		}
	}
} TainthookPass;

PRIVATE_NAMESPACE_END
