# @TEST-EXEC: zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Errors that happen during runtime. At least at the moment we are not checking these early enough
# that Bro will bail out during startup. Perhaps we want to change this later.

option A = 5;
Option::set("B", 6);

@TEST-START-NEXT

option A = 5;
Option::set("A", "hi");

@TEST-START-NEXT

const A = 5;
Option::set("A", 6);

@TEST-START-NEXT:

option A = 5;

function option_changed(ID: string, new_value: bool): bool {
}

Option::set_change_handler("A", option_changed);

@TEST-START-NEXT:

option A = 5;

function option_changed(ID: string): bool {
}

Option::set_change_handler("A", option_changed);

@TEST-START-NEXT:

option A : count = 5;

function option_changed(ID: string, new_value: count): bool {
}

Option::set_change_handler("A", option_changed);

@TEST-START-NEXT:

option A : count = 5;

hook option_changed(ID: string, new_value: count) {
}

Option::set_change_handler("A", option_changed);

@TEST-START-NEXT:

option A : count = 5;

event option_changed(ID: string, new_value: count) {
}

Option::set_change_handler("A", option_changed);

@TEST-START-NEXT:

function option_changed(ID: string, new_value: count) : count {
}

Option::set_change_handler("A", option_changed);


@TEST-START-NEXT:

const A : count = 5;

function option_changed(ID: string, new_value: count) : count {
}

Option::set_change_handler("A", option_changed);

@TEST-START-NEXT:

option A : count = 5;

Option::set_change_handler("A", A);

@TEST-START-NEXT:

option A : count = 5;

function option_changed(ID: string, new_value: count, location: count) : count {
}

Option::set_change_handler("A", option_changed);

@TEST-START-NEXT:

option A : count = 5;

function option_changed(ID: string, new_value: count, location: string, a: count) : count {
}

Option::set_change_handler("A", option_changed);
