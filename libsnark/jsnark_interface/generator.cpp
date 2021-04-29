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
    // this file expects 2 inputs:
    // a circuit description file (something like 'blah.arith')
    // the public+private inputs to the circuit (something like 'blah.in')
    // both of these are produced by jsnark CircuitGenerator.prepFiles('blah');
    // This file produces the following outputs:
    // argv[3] e.g. "/tmp/trisa_verification_key.out" - a verification key for the verifier
    // argv[4] e.g. "/tmp/trisa_proving_key.out" - a proving key for the prover

    assert(argc == 5);
    char * circuit_arith_filepath = argv[1];
    char * circuit_inputs_filepath = argv[2];
    char * verification_key_out_filepath = argv[3];
    char * proving_key_out_filepath = argv[4];

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);



	// Read the circuit, evaluate, and translate constraints
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

	//assert(cs.is_valid());

	// removed cs.is_valid() check due to a suspected (off by 1) issue in a newly added check in their method.
        // A follow-up will be added.
	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		return -1;
	}


	r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);




    libff::enter_block("Call to run_r1cs_ppzksnark");

    libff::print_header("R1CS ppzkSNARK Generator");
    r1cs_ppzksnark_keypair<libff::default_ec_pp> keypair = r1cs_ppzksnark_generator<libff::default_ec_pp>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<libff::default_ec_pp> pvk = r1cs_ppzksnark_verifier_process_vk<libff::default_ec_pp>(keypair.vk);

    // serialize verification key
    ofstream outfile;
    outfile.open(verification_key_out_filepath);
    outfile << keypair.vk;
    outfile.close();

    outfile.open(proving_key_out_filepath);
    outfile << keypair.pk;
    outfile.close();

	return 0;
}

