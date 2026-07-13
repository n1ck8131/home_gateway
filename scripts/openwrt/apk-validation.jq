def dependency_variants($name):
	. == $name or
	. == "!\($name)" or
	startswith("\($name)=") or
	startswith("\($name)<") or
	startswith("\($name)>") or
	startswith("\($name)~") or
	startswith("!\($name)=") or
	startswith("!\($name)<") or
	startswith("!\($name)>") or
	startswith("!\($name)~");

def dependency_conflicts($name):
	. == "!\($name)" or
	startswith("!\($name)=") or
	startswith("!\($name)<") or
	startswith("!\($name)>") or
	startswith("!\($name)~");

def require_dependency_strings($context):
	.info.depends as $depends |
	if ($depends | type) != "array" then
		error("malformed \($context) dependencies: expected a dependency array")
	elif (all($depends[]; type == "string") | not) then
		error("malformed \($context) dependencies: expected dependency strings")
	else
		$depends
	end;

def require_single_dependency($name):
	require_dependency_strings("package") |
	[.[] | select(dependency_variants($name))] as $related |
	if ([$related[] | select(dependency_conflicts($name))] | length) != 0 then
		error("conflicting dependency named \($name) is not allowed")
	elif ([$related[] | select(. != $name)] | length) != 0 then
		error("dependency named \($name) must be an exact unversioned string")
	elif ([$related[] | select(. == $name)] | length) != 1 then
		error("expected exactly one unversioned dependency named \($name)")
	else
		true
	end;

def require_kernel_tuple:
	require_dependency_strings("kmod") |
	[.[] | select(dependency_variants("kernel"))] as $related |
	if ([$related[] | select(dependency_conflicts("kernel"))] | length) != 0 then
		error("conflicting kernel dependency is not allowed")
	elif ($related | length) != 1 then
		error("expected exactly one kernel dependency string")
	elif ($related[0] | test("^kernel=[0-9]+\\.[0-9]+\\.[0-9]+~[0-9a-f]{32}-r1$") | not) then
		error("kernel dependency string has an unexpected format")
	else
		$related[0] | capture("^kernel=(?<kernel>[0-9]+\\.[0-9]+\\.[0-9]+)~(?<vermagic>[0-9a-f]{32})-r1$")
	end;

if $mode == "package-dependency" then
	require_single_dependency($expected)
elif $mode == "kernel" then
	require_kernel_tuple
else
	error("unknown APK validation mode")
end
