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

std::vector<string> split_string(const std::string &in, const std::string &delimiter) {
	std::vector<string> res;
	size_t port_start = 0, port_end;
	while ((port_end = in.find(delimiter, port_start)) != std::string::npos) {
		res.push_back(in.substr(port_start, port_end - port_start));
		port_start = port_end + delimiter.length();
	}
	res.push_back(in.substr(port_start));

	return res;
}

struct AnnoSRAMWorker {
	bool verbose = false;

	void process(RTLIL::Module *module, std::string anno) {
		// type, ops, insts
		std::vector<std::string> anno_args = split_string(anno, ",");

		if (anno_args[0] == "queue") {
			// type, enq, deq, full, insts
			if (anno_args.size() != 5)
				log_error("Invalid queue annotation: %s\n", anno.c_str());

			RTLIL::Wire* queue_enq = module->wire(RTLIL::escape_id(anno_args[1]));
			RTLIL::Wire* queue_deq = module->wire(RTLIL::escape_id(anno_args[2]));
			RTLIL::Wire* queue_full = module->wire(RTLIL::escape_id(anno_args[2]));
			if (queue_enq == nullptr || queue_deq == nullptr || queue_full == nullptr)
				log_error("Not found queue ptr %s %s %s in module\n", anno_args[1].c_str(), anno_args[2].c_str(), anno_args[3].c_str());
			
			std::vector<std::string> insts = split_string(anno_args[4], ";");
			for (auto inst : insts) {
				RTLIL::Cell* wrapper_cell = find_wrapper_cell(module, inst);
				if (wrapper_cell == nullptr)
					log_error("Not found instance %s in module\n", inst.c_str());

				wrapper_cell->setPort(ID(LIVENESS_OP0), queue_enq);
				wrapper_cell->setPort(ID(LIVENESS_OP1), queue_deq);
				wrapper_cell->setPort(ID(LIVENESS_OP2), queue_full);

				int op_widths = std::max(queue_enq->width, queue_deq->width);
				RTLIL::Module *wrapper_module = module->design->module(wrapper_cell->type);
				if (wrapper_module == nullptr)
					log_error("Not found SRAM Wrapper module %s for instance %s\n",
						wrapper_cell->type.c_str(),
						wrapper_cell->name.c_str()
					);

				anno_sram(wrapper_module, op_widths, "queue");
			}
		}
		else if (anno_args[0] == "bitmap") {
			// type, vector, insts
			if (anno_args.size() != 3)
				log_error("Invalid bitmap annotation: %s\n", anno.c_str());

			RTLIL::Wire* valid_vector = module->wire(RTLIL::escape_id(anno_args[1]));
			if (valid_vector == nullptr)
				log_error("Not found vector %s in module\n", anno_args[1].c_str());

			std::vector<std::string> insts = split_string(anno_args[2], ";");
			for (auto inst : insts) {
				if (verbose)
					log("Instrument instance %s\n", inst.c_str());

				RTLIL::Cell* wrapper_cell = find_wrapper_cell(module, inst);
				if (wrapper_cell == nullptr)
					log_error("Not found instance %s in module\n", inst.c_str());

				wrapper_cell->setPort(ID(LIVENESS_OP0), valid_vector);

				int op_widths = valid_vector->width;
				RTLIL::Module *wrapper_module = module->design->module(wrapper_cell->type);
				if (wrapper_module == nullptr)
					log_error("Not found SRAM Wrapper module %s for instance %s\n",
						wrapper_cell->type.c_str(),
						wrapper_cell->name.c_str()
					);

				anno_sram(wrapper_module, op_widths, "bitmap");
			}
		}
	}

	RTLIL::Cell* find_wrapper_cell(RTLIL::Module* module, std::string target) {
		RTLIL::Cell* wrapper_cell = module->cell(RTLIL::escape_id(target));
		
		if (wrapper_cell == nullptr) {
			log("Not found instance %s, try alias %s\n", target.c_str(), (target + "_0").c_str());
			wrapper_cell = module->cell(RTLIL::escape_id(target + "_0"));
		}

		if (wrapper_cell == nullptr)
			log_error("Not found instance %s in module\n", target.c_str());
		
		return wrapper_cell;
	}

	void anno_sram (RTLIL::Module *wrapper_module, int op_widths, std::string liveness_type) {
		if (wrapper_module->get_bool_attribute(ID(divaift_sram_liveness_done)))
			return;

		RTLIL::Wire *bypass_op0 = wrapper_module->addWire(ID(LIVENESS_OP0), op_widths);
		RTLIL::Wire *bypass_op1 = wrapper_module->addWire(ID(LIVENESS_OP1), op_widths);
		RTLIL::Wire *bypass_op2 = wrapper_module->addWire(ID(LIVENESS_OP2), op_widths);
		bypass_op0->port_input = true;
		bypass_op1->port_input = true;
		bypass_op2->port_input = true;
		wrapper_module->fixup_ports();

		for (auto sram_cell : wrapper_module->cells()) {
			if (sram_cell->type.isPublic()) {
				sram_cell->setPort(ID(LIVENESS_OP0), bypass_op0);
				sram_cell->setPort(ID(LIVENESS_OP1), bypass_op1);
				sram_cell->setPort(ID(LIVENESS_OP2), bypass_op2);

				RTLIL::Module *sram_module = wrapper_module->design->module(sram_cell->type);
				if (sram_module == nullptr)
					log_error("Not found SRAM module %s for instance %s\n",
						sram_cell->type.c_str(),
						sram_cell->name.c_str()
					);

				RTLIL::Wire *op0 = sram_module->addWire(ID(LIVENESS_OP0), op_widths);
				RTLIL::Wire *op1 = sram_module->addWire(ID(LIVENESS_OP1), op_widths);
				RTLIL::Wire *op2 = sram_module->addWire(ID(LIVENESS_OP2), op_widths);
				op0->port_input = true;
				op1->port_input = true;
				op2->port_input = true;
				sram_module->fixup_ports();

				bool meet_sram = false;
				for (auto sram_array : sram_module->cells()) {
					if (sram_array->type == ID(taintcell_mem)) {
						meet_sram = true;
						sram_array->setParam(ID(LIVENESS_TYPE), liveness_type);
						sram_array->setPort(ID(LIVENESS_OP0), op0);
						sram_array->setPort(ID(LIVENESS_OP1), op1);
						sram_array->setPort(ID(LIVENESS_OP2), op2);
					}
				}
				
				if (!meet_sram) {
					log_cmd_error("No sram cell found in module %s\n", sram_module->name.c_str());
				}
			}
		}

		wrapper_module->set_bool_attribute(ID(divaift_sram_liveness_done), true);
	}
};

struct AnnoSRAMPass : public Pass {
	AnnoSRAMPass() : Pass("anno_chisel_sram") {}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override {
		log_header(design, "Annotate liveness information on external chisel sram\n");
		AnnoSRAMWorker worker;

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "--verbose") {
				worker.verbose = true;
				continue;
			}
		}
		extra_args(args, argidx, design);

		for (RTLIL::Module *module : design->modules()) {
			if (module->has_attribute(ID(divaift_sram_liveness))) {
				if (worker.verbose)
					log("Catch SRAM liveness information on module %s\n", module->name.c_str());
				std::string anno = module->get_string_attribute(ID(divaift_sram_liveness));
				worker.process(module, anno);
			}
			else if (module->wire(ID(divaift_sram_hint)) != nullptr) {
				if (worker.verbose)
					log("Catch SRAM liveness hint signal in module %s\n", module->name.c_str());
				std::string anno = module->wire(ID(divaift_sram_hint))->get_string_attribute(ID(divaift_sram_liveness));
				worker.process(module, anno);
			}
		}
	}
} AnnoSRAMPass;

PRIVATE_NAMESPACE_END
