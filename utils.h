using namespace std;
using namespace CryptoPP;

int safe_remove_from_disk(string path);
int safe_move_on_disk(string path, string new_path);
void safe_delete_binary_data(byte* ptr, size_t size);
void safe_delete_sec_byte_block(SecByteBlock* block);
