#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

#define ID2NAME(id) (id.str().substr(1))
#define NameTaint(id, t_id) (id.str() + "_t_" + std::to_string(t_id))
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
	unsigned int taint_num = 1;
	std::vector<string> ignore_ports;

	void taint_port(RTLIL::Module *module)
	{
		bool done = module->get_bool_attribute(ID(pift_port_tainted));
		if (done)
			return;

		for (auto w : module->wires().to_vector()) {
			if (w->port_input && !in_list(ID2NAME(w->name), ignore_ports)) {
				if (verbose)
					log("\texpand input port: %s\n", w->name.c_str());
				for (unsigned int taint_id = 0; taint_id < taint_num; taint_id++) {
					RTLIL::Wire *w_t = module->addWire(ID2NAMETaint(w->name, taint_id), w->width);
					w_t->port_input = true;
				}
			} else if (w->port_output && !in_list(ID2NAME(w->name), ignore_ports)) {
				if (verbose)
					log("\texpand output port: %s\n", w->name.c_str());
				for (unsigned int taint_id = 0; taint_id < taint_num; taint_id++) {
					RTLIL::Wire *w_t = module->addWire(ID2NAMETaint(w->name, taint_id), w->width);
					w_t->port_output = true;
				}
			}
		}
		module->fixup_ports();
		module->set_bool_attribute(ID(pift_port_tainted), true);
	}

	void instrument(RTLIL::Module *module) {
		taint_port(module);
	}
};

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
				worker.taint_num = std::stoi(args[++argidx]);
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
			log("[*] Taint Width: %d\n", worker.taint_num);
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
