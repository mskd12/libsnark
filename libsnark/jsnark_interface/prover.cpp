/*
 * prover.cpp
 * Adapted from run_ppzksnark.cpp
 *
 *      Author: Deepak Maram
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

int main(int argc, char **argv) {

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	int inputStartIndex = 0;
	if(argc == 4){
		if(strcmp(argv[1], "gg") != 0){
			cout << "Invalid Argument - Terminating.." << endl;
			return -1;
		} else{
			cout << "Using ppzsknark in the generic group model [Gro16]." << endl;
		}
		inputStartIndex = 1;	
	} 	

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());

    // Serialize public input (and output).
	ofstream outfile;
	outfile.open("public_input.in");
    outfile << primary_input;
	// std::vector<Wire> inputList = reader.getInputWireIds();
	// int start = 0;
	// int end = reader.getNumInputs();
	// for (int i = start ; i < end; i++) {
	// 	outfile << inputList[i] << " " << primary_input[i] << endl;
	// }
	// std::vector<Wire> outputList = reader.getOutputWireIds();
	// start = reader.getNumInputs();
	// end = reader.getNumInputs() +reader.getNumOutputs();	
	// for (int i = start ; i < end; i++) {
	// 	outfile << outputList[i-reader.getNumInputs()] << " " << primary_input[i] << endl;
	// }
	outfile.close();

	//assert(cs.is_valid());

	// removed cs.is_valid() check due to a suspected (off by 1) issue in a newly added check in their method.
        // A follow-up will be added.
	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
	}


	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);
	
	const bool test_serialization = false;
	bool successBit = false;
	if(argc == 3) {
		libff::enter_block("Call to run_r1cs_ppzksnark");

		libff::print_header("R1CS ppzkSNARK Generator");
		r1cs_ppzksnark_keypair<libff::default_ec_pp> keypair = r1cs_ppzksnark_generator<libff::default_ec_pp>(example.constraint_system);
		printf("\n"); libff::print_indent(); libff::print_mem("after generator");

		libff::print_header("Preprocess verification key");
		r1cs_ppzksnark_processed_verification_key<libff::default_ec_pp> pvk = r1cs_ppzksnark_verifier_process_vk<libff::default_ec_pp>(keypair.vk);
		
        // serialize verification key
        outfile.open("verification_key.out");
		outfile << keypair.vk;
		outfile.close();

		libff::print_header("R1CS ppzkSNARK Prover");
		r1cs_ppzksnark_proof<libff::default_ec_pp> proof = r1cs_ppzksnark_prover<libff::default_ec_pp>(keypair.pk, example.primary_input, example.auxiliary_input);
		printf("\n"); libff::print_indent(); libff::print_mem("after prover");

		// serialize proof
		outfile.open("proof.out");
		outfile << proof;
		outfile.close();
	} else {
		// The following code makes use of the observation that 
		// libsnark::default_r1cs_gg_ppzksnark_pp is the same as libff::default_ec_pp (see r1cs_gg_ppzksnark_pp.hpp)
		// otherwise, the following code won't work properly, as GadgetLib2 is hardcoded to use libff::default_ec_pp.
		successBit = libsnark::run_r1cs_gg_ppzksnark<libsnark::default_r1cs_gg_ppzksnark_pp>(
			example, test_serialization);
	}

	return 0;
}

