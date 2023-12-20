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

struct mod_info_t {
	RTLIL::Module *module;
	bool has_memory = false;
	bool has_handshake_port = false;
	std::set<RTLIL::IdString> child;
};

struct TSINKWorker {
	bool verbose = false;
	std::map<RTLIL::IdString, mod_info_t> mod_stat;
	std::set<RTLIL::IdString> selected;

	mod_info_t process(RTLIL::Module *module) {
		mod_info_t info;
		info.module = module;
		for (auto port : module->ports) {
			if (port.contains("_valid")) {
				info.has_handshake_port = true;
				break;
			}
		}

		for (auto cell : module->cells().to_vector()) {
			if (cell->type == ID($mem_v2)) {
				if (verbose)
					log("// \t%s#memory\n", cell->name.c_str());
				info.has_memory = true;
				continue;
			}
			if (cell->type.isPublic()) {
				if (verbose)
					log("// \t%s@%s\n", cell->name.c_str(), cell->type.c_str());
				info.child.insert(cell->type);
			}
		}

		return info;
	}

	bool walk_hierarchy(RTLIL::Module *entry) {
		mod_info_t current = mod_stat[entry->name];
		bool has_memory = current.has_memory;
		for (auto child : current.child) {
			has_memory |= walk_hierarchy(mod_stat[child].module);
		}

		if (current.has_handshake_port && has_memory) {
			selected.insert(entry->name);
		}

		return has_memory;
	}
};


struct TaintSinkPass : public Pass {
	TaintSinkPass() : Pass("tsink") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Figure out potential taint sinks module \n");
		TSINKWorker worker;
		RTLIL::Module *top = nullptr;
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
			if (args[argidx] == "--top" && argidx+1 < args.size()) {
				if (design->module(RTLIL::escape_id(args[argidx+1])) == nullptr)
					log_cmd_error("Can't find module %s.\n", args[argidx+1].c_str());
				top = design->module(RTLIL::escape_id(args[++argidx]));
				continue;
			}
		}
		extra_args(args, argidx, design);

		for (RTLIL::Module *module : design->modules()) {
			if (worker.verbose)
				log("// module %s @%s\n", module->name.c_str(), module->get_src_attribute().c_str());
			worker.mod_stat[module->name] = worker.process(module);
		}
		worker.walk_hierarchy(top);
		for (auto out : worker.selected) {
			log("%s\n", log_id(out));
		}
	}
} TaintSinkPass;

PRIVATE_NAMESPACE_END
