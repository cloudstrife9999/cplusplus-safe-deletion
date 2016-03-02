#include <utils.h>
#include <stdio.h>

//deletes a file on disk by fully overwriting it with zeroes, then calling the remove primitive (sorry forensics LOL).
//however you must have rw permissions on the location.
int safe_remove_from_disk(string path) {
	FILE* f = fopen(path.c_str(), "wb");

	if(f != NULL) {
		//getting the file size in bytes
		fseek(f, 0, SEEK_END);
		int size = ftell(f);
		fseek(f, 0, SEEK_SET);


		byte* content = (byte*) malloc(size * sizeof(byte));

		//no problem here with compiler optimizations due to the previous content being random (A.K.A. uninteresting).
		memset(content, 0x00, size);

		//overwriting the file with 0x00 bytes.
		fwrite(content, sizeof(byte), size, f);
		free(content);
		fclose(f);
	}

	//now we can delete the file.
	return remove(path.c_str());
}

//moves a file leaving no traces on disk (A.K.A. forensics to retrieve the old file becomes useless).
//however you must have rw permissions on both locations.
int safe_move_on_disk(string path, string new_path) {
	ifstream src(path, ios::binary);
	ofstream dst(new_path, ios::binary);

	//that's a "copy".
	dst << src.rdbuf();
	src.close();
	dst.close();

	//now we "safely delete" the original file.
	return safe_remove_from_disk(path);
}

//Deletes a byte array from the memory by overwriting it with zeroes, then deallocating it.
void safe_delete_binary_data(byte* ptr, size_t size) {
	//safer than memset(ptr, 0x00, size) due to bad (for security) optimizations using registers not cleared after.
	for(size_t i=0; i<size; i++) {
		memset(ptr + i, 0x00, 1);

		//to prevent possible optimizations transforming the for loop into a single memset.
		int j = 0;
		memset(ptr + i + j, 0x00, 1);
	}

	//release the "lock" on the (formerly) allocated (heap) memory.
	free(ptr);

	//paranoid level = insane
	size = 0;
}

//Deletes a SecByteBloc from the memory by overwriting the relevant fields with zeroes, then deallocating it.
void safe_delete_sec_byte_block(SecByteBlock* block) {
	size_t size = block->SizeInBytes();

	//safer than memset(block->data(), 0x00, size) due to bad (for security) optimizations using registers not cleared after.
	for(size_t i=0; i<size; i++) {
		memset(block->data() + i, 0x00, 1);

		//to prevent possible optimizations transforming the for loop into a single memset.
		int j = 0;
		memset(block->data() + i + j, 0x00, 1);
	}

	//paranoid mode: new initialization with a byte array full of 0x00 with the same size of the previous one.
	block->CleanNew(size);
	byte* ptr = (byte*) malloc(size * sizeof(byte));

	//see above.
	for(size_t i=0; i<size; i++) {
		ptr[i] = 0x00;
	}

	//see above
	*block = SecByteBlock(ptr, size);

	//deletion
	block->CleanNew(0);

	//deletion of the byte array
	safe_delete_binary_data(ptr, size);

	//paranoid level = insane
	size = 0;
}
