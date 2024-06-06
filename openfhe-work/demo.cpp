#include "openfhe.h"
#include <math.h>
#include <cmath>
#include <vector>
#include <ctype.h>
#include <string>

using namespace lbcrypto;

Plaintext maskCreate(std::vector<int64_t> m, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    auto plM = cryptoContext->MakePackedPlaintext(m);
    return plM;
}

Plaintext identityMask(int size, int slots, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    std::vector<int64_t> v = {};
    for (int i = 1; i <= slots; i++) {
        if (i % (size) == 0) {
            v.push_back(0);
        } else {
            v.push_back(1);
        }
    }
    return maskCreate(v, cryptoContext, keys);
}

Plaintext maskGenerate(int size, int index, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    std::vector<int64_t> v = {};
    while(v.size() < size) {
        for (int i = 0; i < pow(2, index)-1; i++) {
            v.push_back(0);
        }
        v.push_back(1);
    }
    v.resize(size);
    return maskCreate(v, cryptoContext, keys);
}

Plaintext clearMaskGenerate(int size, int slots, int index, CryptoContext<DCRTPoly> cryptoContext, KeyPair<DCRTPoly> keys) {
    std::vector<int64_t> v = {};
    int count = 1;
    while(v.size() < slots) {
        for (int i = 0; i < pow(2, index-1)-1; i++) {
            v.push_back(1);
            count += 1;
        }
        if (count % ((int)pow(2, index)) == 0) {
            v.push_back(1);
            count += 1;
        } else {
            v.push_back(0);
            count += 1;
        }
        
    }
    return maskCreate(v, cryptoContext, keys);
}


Ciphertext<DCRTPoly> upSweep(Ciphertext<DCRTPoly> cipher, CryptoContext<DCRTPoly> cryptoContext, int size, int slots, KeyPair<DCRTPoly> keys) {
    //for each level of the tree of height log_2 n
    for (int index = 1; index < log2(size)+1; index++) {
        //generate mask for that level
        auto cipherMask = maskGenerate(slots, index, cryptoContext, keys);

        //rotate cipher so elems are matching mask
        auto cipherRot = cryptoContext->EvalRotate(cipher, -pow(2, index-1));

        //create vector to be summed for this step
        auto addSum = cryptoContext->EvalMult(cipherRot, cipherMask);

        //Eval Add
        auto result = cryptoContext->EvalAdd(addSum, cipher);
        cipher = result;

        Plaintext plresult2;
        cryptoContext->Decrypt(keys.secretKey, cipher, &plresult2);
        plresult2->SetLength(2*size);
        std::cout << " run " << index << ": " << plresult2;
        std::cout << std::endl;
    }
    return cipher;
}

Ciphertext<DCRTPoly> downSweep(Ciphertext<DCRTPoly> cipher, CryptoContext<DCRTPoly> cryptoContext, int size, int slots, KeyPair<DCRTPoly> keys) {
    //generate masks
    auto idMask = identityMask(size, slots, cryptoContext, keys);

    //Set identity to end of vector
    cipher = cryptoContext->EvalMult(cipher, idMask);

    for (int index = log2(size); index >= 1; index--) {
        auto cipherMask = maskGenerate(slots, index-1, cryptoContext, keys);
        cipherMask->SetLength(32);

        //obtain target values (the left subchild of roots and the value of the root)
        auto children = cryptoContext->EvalMult(cipher, cipherMask);

        Plaintext plresult;
        cryptoContext->Decrypt(keys.secretKey, cipher, &plresult);
        plresult->SetLength(2*size);
        std::cout << " run " << log2(size) - index + 1 << ": " << plresult;
        std::cout << std::endl;

        //rotate the subchild and root values and add to do the first operation of setting the roots as left + root
        children = cryptoContext->EvalRotate(children, - pow(2, index-1));

 

        auto result1 = cryptoContext->EvalAdd(children, cipher);


        auto prevMask = maskGenerate(slots, index, cryptoContext, keys);

        //Begin second operation by obtaining values of roots only
        auto roots = cryptoContext->EvalMult(cipher, prevMask);

        //Clear existing values
        auto clearMask = clearMaskGenerate(size, slots, index, cryptoContext, keys);

        auto cleared = cryptoContext->EvalMult(clearMask, result1);
        cleared = cryptoContext->Relinearize(cleared);

        //Rotate and add
        roots = cryptoContext->EvalRotate(roots, pow(2, index-1));

        auto result2 = cryptoContext->EvalAdd(roots, cleared);

        cipher = result2; 

        Plaintext plresult2;
        cryptoContext->Decrypt(keys.secretKey, result2, &plresult2);
        plresult2->SetLength(2*size);
        std::cout << " run " << log2(size) - index + 1 << ": " << plresult2;
        std::cout << std::endl;
    }
    return cipher;
}

void prefixSum(std::vector<int64_t> v, int size) {
    std::vector<int> rotate_Index = {};
    for (int i = 0; i <= v.size(); i++) {
        rotate_Index.push_back(i);
        rotate_Index.push_back(-i);
    }

    //set params
    CCParams<CryptoContextBGVRNS> params;
    params.SetPlaintextModulus(257); // p
    params.SetRingDim(128); // n =  m/2
    params.SetMultiplicativeDepth(50); // no. q
    params.SetMaxRelinSkDeg(3);
    params.SetSecurityLevel(HEStd_NotSet);
    // params.SetBatchSize(2*vector.size());
    // params.SetScalingTechnique(FLEXIBLEAUTO);
    // params.SetScalingModSize(60);
    // params.SetMultiplicationTechnique(BEHZ);

    //create context
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(params);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n (slot count)= " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    //key generation
    KeyPair<DCRTPoly> keys = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keys.secretKey);
    cryptoContext->EvalRotateKeyGen(keys.secretKey, rotate_Index);

    //encryption
    Plaintext plaintext = cryptoContext->MakePackedPlaintext(v);
    std::cout << "Initial Vector: " << plaintext << std::endl;
    auto cipher = cryptoContext->Encrypt(keys.publicKey, plaintext);

    //test
    std::cout << "upsweep" << std::endl;
    cipher = upSweep(cipher, cryptoContext, size, v.size(), keys);  

    std::cout << "downsweep" << std::endl;
    cipher = downSweep(cipher, cryptoContext, size, v.size(), keys);

        Plaintext plresult3;
        cryptoContext->Decrypt(keys.secretKey, cipher, &plresult3);
        plresult3->SetLength(32);
        std::cout << "Results: ";
        std::cout << plresult3;
        std::cout << std::endl;
}

std::vector<int64_t> pad (std::vector<int64_t> v, int size) {
    int vsize = v.size();
    for (int i = 0; i < size - vsize; i++) {
        v.push_back(0);
    }
    return v;
}

//assume balanced binary tree (size of plaintext is size of 2**n exactly), later function to pad to 2**n if needed

int main() {
    std::vector<int64_t> vector;


    vector = {1,6,4,2,5,3}; //Change this vector to change vector to be prefix summed


    int vectorSize = pow(2, (int)log2(vector.size())+1);
    vector = pad(vector, vectorSize);
    std::vector<int64_t> vector2(vector);

    for (int i = 0; i < (128/vectorSize)-1; i++) {
        vector.insert(vector.end(), vector2.begin(), vector2.end());
    }
    prefixSum(vector, vectorSize);

    return 0;
}

