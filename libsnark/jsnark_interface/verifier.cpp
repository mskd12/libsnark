/*
 * verifier.cpp
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

	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();

    ifstream infile;
    r1cs_ppzksnark_proof<libff::default_ec_pp> proof = r1cs_ppzksnark_proof<libff::default_ec_pp>();
    infile.open("proof.out");
    infile >> proof;
    infile.close();
    cout << "Deserialized proof" << endl;

    r1cs_ppzksnark_verification_key<libff::default_ec_pp> vk = r1cs_ppzksnark_verification_key<libff::default_ec_pp>();
    infile.open("verification_key.out");
    infile >> vk;
    infile.close();
    cout << "Deserialized verification key" << endl;

    r1cs_primary_input<FieldT> primary_input;
    infile.open("public_input.in");
    infile >> primary_input;
    infile.close();
    cout << "Deserialized public input" << endl;

    libff::print_header("R1CS ppzkSNARK Verifier");
    const bool ans = r1cs_ppzksnark_verifier_strong_IC<libff::default_ec_pp>(vk, primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    if (!ans) {
		cout << "Problem occurred while running the ppzksnark algorithms .. " << endl;
		return -1;
    }
    return 0;
}
