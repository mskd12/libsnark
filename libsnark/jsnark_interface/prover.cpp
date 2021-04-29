
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
#include <assert.h>

int main(int argc, char **argv) {
    // this file expects 4 inputs:
    // a circuit description file (something like 'blah.arith')
    // the public+private inputs to the circuit (something like 'blah.in')
    // both of these are produced by jsnark CircuitGenerator.prepFiles('blah');
    // This file also expects that you ran generator.cpp which creates the following file:
    // argv[3] - something like "/tmp/trisa_proving_key.out" - the key the prover uses
    // This file produces the following outputs:
    // argv[4] - "/tmp/trisa_proof.out" - the zk proof
    // argv[5] - "/tmp/trisa_public_input.in" - the public inputs to the circuit
    // which you can then provide to the verifier with the verification key to validate the circuit is correct.

    assert(argc == 6);
    char * circuit_arith_filepath = argv[1];
    char * circuit_inputs_filepath = argv[2];
    char * proving_key_filepath = argv[3];

    char * proof_out_filepath = argv[4];
    char * public_inputs_out_filepath = argv[5];


	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);


	CircuitReader reader(circuit_arith_filepath, circuit_inputs_filepath, pb);
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
	outfile.open(public_inputs_out_filepath);
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


    ifstream infile;
    r1cs_ppzksnark_proving_key<libff::default_ec_pp> pk = r1cs_ppzksnark_proving_key<libff::default_ec_pp>();
    infile.open(proving_key_filepath);
    infile >> pk;
    infile.close();
    cout << "Deserialized proving key" << endl;


    libff::print_header("R1CS ppzkSNARK Prover");
    r1cs_ppzksnark_proof<libff::default_ec_pp> proof = r1cs_ppzksnark_prover<libff::default_ec_pp>(pk, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    // serialize proof
    outfile.open(proof_out_filepath);
    outfile << proof;
    outfile.close();


	return 0;
}
