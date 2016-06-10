module natop.exceptions;

class NATOPException : Exception
{
	@safe pure nothrow this(string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{
		super("NAT Opener Exception: " ~ err, next, file, line);
	}
}

class NATPMPException : Exception
{
	@safe pure nothrow this(string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{
		super("NATPMP Exception: " ~ err, next, file, line);
	}
}

class PortConflictException : NATOPException
{
	@safe pure nothrow this(string err, Throwable next = null, string file = __FILE__, int line = __LINE__)
	{
		super("Port Conflict Exception: " ~ err, next, file, line);
	}
}