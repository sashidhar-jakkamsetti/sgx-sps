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

#include <string.h>
#include <vector>
#include "../Globals.hpp"
#include "../CONFIG.h"
#include "../CONFIG_FLAGS.h"
#include "Globals_Enclave.hpp"
#include "Enclave_utils.hpp"
#include "ORAMTree.hpp"
#include "PathORAM_Enclave.hpp"
#include "CircuitORAM_Enclave.hpp"
#include "LinearScan_ORAM.hpp"

#include "crypto.h"
#include "datatypes.h"


#include "tsgxsslio.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>


std::vector<PathORAM *> poram_instances;
std::vector<CircuitORAM *> coram_instances;
std::vector<LinearScan_ORAM *> lsoram_instances;

uint32_t poram_instance_id=0;
uint32_t coram_instance_id=0;
uint32_t lsoram_instance_id = 0;



/*  ================================================================================  */
/*               SCALABLE PRIVATE SIGNALING ___ CODE EDITS/FUNCTIONS                  */
/*  ================================================================================  */

static bool is_init = false;

static int ctr_recip = 0;
static int ctr_msg = 0;

typedef struct sps_orams_t {
	PathORAM *msg;
	PathORAM *recp;
	CircuitORAM *msg1;
	CircuitORAM *recp1;
} sps_orams_t;


static sps_orams_t sps_orams;
static sps_keychain_t sps_keys;

inline void clearData(unsigned char* data, int start, int len) {
	memset(data + start, -1, len - start);
}

/*  ================================================================================  */
