#include "driver.hpp"
#include <iostream>

int main()
{
	printf("Setup: %d\n", driver::setup());
	
	cmd_t cmd{};
	cmd.verification_code = SYSCALL_CODE;

	cmd.operation = memory_read;
	printf("Read sent: %d\n", driver::send_cmd(&cmd));

	cmd.operation = memory_write;
	printf("Write sent: %d\n", driver::send_cmd(&cmd));

	cmd.operation = module_base;
	printf("Module base sent: %d\n", driver::send_cmd(&cmd));

	getchar();

	return 0;
}