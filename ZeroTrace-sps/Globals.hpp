/*
*    ZeroTrace: Oblivious Memory Primitives from Intel SGX 
*    Copyright (C) 2018  Sajin (sshsshy)
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, version 3 of the License.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef __GLOBALS__
  
  #include<stdint.h>

  //Global Flags

  // Global Declarations

  #define ADDITIONAL_METADATA_SIZE 24
  #define HASH_LENGTH 32
  #define NONCE_LENGTH 16
  #define KEY_LENGTH 16
  #define MILLION 1E6
  #define IV_LENGTH 12
  #define ID_SIZE_IN_BYTES 4
  #define EC_KEY_SIZE 32
  #define KEY_LENGTH 16
  #define TAG_SIZE 16
  #define CLOCKS_PER_MS (CLOCKS_PER_SEC/1000)
  #define AES_GCM_BLOCK_SIZE_IN_BYTES 16
  #define PRIME256V1_KEY_SIZE 32



  //Other Global variables
  const char SHARED_AES_KEY[KEY_LENGTH] = {"AAAAAAAAAAAAAAA"};
  const char HARDCODED_IV[IV_LENGTH] = {"AAAAAAAAAAA"};

  //Hard-coded Enclave Signing key
  //This key would ideally be sampled and signed in the Remote attestation phase with a client
  //Currently we use a static hard coded ECDSA key for it.
   
  static unsigned char hardcoded_verification_key_x[PRIME256V1_KEY_SIZE] = 
	  {0x45, 0xb2, 0x00, 0x83, 0x53, 0x11, 0x4b, 0xbb,
	   0x78, 0xeb, 0x67, 0x17, 0xf2, 0xc9, 0x51, 0xe4,
	   0xcc, 0x1d, 0x93, 0x89, 0x0c, 0x70, 0xe1, 0x93,
	   0xcc, 0xd2, 0x83, 0x01, 0x68, 0x61, 0xe6, 0xec};

  static unsigned char hardcoded_verification_key_y[PRIME256V1_KEY_SIZE] =
	  {0xde, 0x24, 0xec, 0x0b, 0xf9, 0x0c, 0x03, 0x27,
	   0xb8, 0x1b, 0x89, 0x40, 0x80, 0x28, 0x54, 0xd8,
	   0xfb, 0xa5, 0xc8, 0x07, 0x57, 0x4c, 0x38, 0xab,
	   0xc3, 0x3e, 0xfb, 0x68, 0x42, 0xd1, 0xa5, 0xcf};

  enum LSORAM_STORAGE_MODES{ INSIDE_PRM, OUTSIDE_PRM};
  enum LSORAM_OBLV_MODES{ACCESS_OBLV, FULL_OBLV};
  enum LSORAM_ERRORCODES{KEY_SIZE_OUT_OF_BOUND, VALUE_SIZE_OUT_OF_BOUND};

  #ifndef TRUE
  # define TRUE 1
  #endif

  #ifndef FALSE
  # define FALSE 0
  #endif

  typedef struct{
    unsigned char *key;
    unsigned char *value;
  }tuple;

  typedef struct detailed_microbenchmarks{
   double posmap_time;
   double download_path_time;
   double fetch_block_time;
   double eviction_time;
   double upload_path_time; 
   double total_time; 
  }det_mb;

  //Inline Functions
  inline uint32_t iBitsPrefix(uint32_t n, uint32_t w, uint32_t i){
    return (~((1<<(w-i)) - 1)) & n;
  }

  inline uint32_t ShiftBy(uint32_t n, uint32_t w) {
    return(n>>w);
  }

  inline uint32_t noOfBitsIn(uint32_t local_deepest){
    uint32_t count = 0;
    while(local_deepest!=0){
      local_deepest = local_deepest >>1;
      count++;
    }
    return count;
  }

  inline bool isBlockDummy(unsigned char *serialized_block, uint64_t gN){
    bool dummy_flag = *((uint32_t*)(serialized_block+16))==gN;
    return dummy_flag;
  }

  inline uint32_t getId(unsigned char *serialized_block){
    uint32_t id = *((uint32_t*)(serialized_block+16));
    return id;
  }

  inline uint32_t* getIdPtr(unsigned char *serialized_block){
    uint32_t *id = ((uint32_t*)(serialized_block+16));
    return id;
  }

  inline void setId(unsigned char *serialized_block, uint32_t new_id){
    *((uint32_t*)(serialized_block+16)) = new_id;
  }

  inline uint32_t getTreeLabel(unsigned char *serialized_block){
    uint32_t treeLabel = *((uint32_t*)(serialized_block+20));
    return treeLabel;
  }

  inline uint32_t* getTreeLabelPtr(unsigned char *serialized_block){
    uint32_t *labelptr = ((uint32_t*)(serialized_block+20));
    return labelptr;
  }

  inline void setTreeLabel(unsigned char *serialized_block, uint32_t new_treelabel){
    *((uint32_t*)(serialized_block+20)) = new_treelabel;
  }

  inline unsigned char* getDataPtr(unsigned char* decrypted_path_ptr){
    return (unsigned char*) (decrypted_path_ptr+24);
  }



/*  ================================================================================  */
/*               SCALABLE PRIVATE SIGNALING ___ CODE EDITS/FUNCTIONS                  */
/*  ================================================================================  */


  /* Cryptographic parameters */
  #define RSA_KEY_BITS 2048
  #define AES_GCM_KEY_BITS 128
  #define AES_GCM_IV_BYTES 12
  #define AES_GCM_TAG_BYTES 16
  #define EC_PK_SIZE_BYTES 65
  #define ECDSA_SIG_SIZE_BYTES 80
  #define RSA_PK_SIZE_BYTES 270


  /* Recipient parameters */
  #define RECIPIENT_DATA_BITS 16


  /* Service parameters (fully configurable)*/
  #define SERVICE_MAX_RECIPIENTS 500  // For comparison with related work
  // #define SERVICE_MAX_RECIPIENTS 1048572
  // #define SERVICE_MAX_RECIPIENTS 16380
  // #define SERVICE_MAX_RECIPIENTS 1020
  // #define SERVICE_MAX_RECIPIENTS 124
  // #define SERVICE_MAX_RECIPIENTS 12

  #define SERVICE_MAX_MESSAGES 500000 // For comparison with related work
  // #define SERVICE_MAX_MESSAGES 134271724
  // #define SERVICE_MAX_MESSAGES 16777212
  // #define SERVICE_MAX_MESSAGES 1048572
  // #define SERVICE_MAX_MESSAGES 16380
  // #define SERVICE_MAX_MESSAGES 1020
  // #define SERVICE_MAX_MESSAGES 124

  #define SERVICE_BATCH_RECEIVE 1     // For comparison with related work


  /* ORAM parameters */
  #define ORAM_BLOCK_SIZE (3*sizeof(int) + 2*EC_PK_SIZE_BYTES)
  #define ORAM_BLOCK_SIZE_MSG  (3*sizeof(int))
  #define ORAM_BLOCK_SIZE_RECP (4*sizeof(int) + 2*EC_PK_SIZE_BYTES)
  #define ORAM_BUCKET_SIZE 4
  #define ORAM_STASH_SIZE_MSG 250
  #define ORAM_STASH_SIZE_RECP 100
  #define ORAM_REC_DATA_SIZE 64
  #define ORAM_ACCESS_BATCH_SIZE 32
  #define ORAM_TYPE_ZT 0


  /***************************************************
   * Enclave return codes
   ***************************************************/
  #define RET_SUCCESS 0
  #define ERROR_INVALID_ARGUMENTS 1
  #define ERROR_ORAM_RETURN_ERROR 2
  #define ERROR_USER_AUTH_FAILED 3
  #define ERROR_SERVICE_RUNNING 4
  #define ERROR_SERVICE_NOT_RUNNING 5
  #define ERROR_OCALL_FAILED 6
  #define ERROR_BUCKET_SIZE_INCONSISTENT 7
  #define ERROR_ORAM_INDEX_OOR 8
  #define ERROR_ORAM_ENCRYPTION_FAILED 9
  #define ERROR_SERVICE_DECRYPTION_FAILED 10
  #define ERROR_VARIABLE_SIZE_INCONSISTENT 11

  #define NAME_MESSAGES_ORAM "MESSAGES_ORAM"
  #define NAME_RECIPIENTS_ORAM "RECIPIENTS_ORAM"

/*  ================================================================================  */


  #define __GLOBALS__
#endif

