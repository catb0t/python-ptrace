import signal
import logging
import errno
import os
from ctypes import sizeof, c_char_p
from six import b

from ptrace import (binding, ctypes_tools, disasm, os_tools, tools, cpu_info)
from ptrace.binding import cpu

from ptrace.error import PtraceError
from ptrace.debugger import (Breakpoint,
                             ProcessExit, ProcessSignal, NewProcessEvent,
                             ProcessExecution)

from ptrace.debugger.backtrace import getBacktrace
from ptrace.debugger.process_error import ProcessError
from ptrace.debugger.memory_mapping import readProcessMappings
from ptrace.debugger.syscall_state import SyscallState

if binding.HAS_PTRACE_SINGLESTEP:
    from ptrace.binding import ptrace_singlestep
if binding.HAS_PTRACE_SIGINFO:
    from ptrace.binding import ptrace_getsiginfo
if binding.HAS_PTRACE_IO:
    from ctypes import create_string_buffer, addressof
    from ptrace.binding import (
        ptrace_io, ptrace_io_desc,
        PIOD_READ_D, PIOD_WRITE_D)
if binding.HAS_PTRACE_EVENTS:
    from ptrace.binding import (
        ptrace_setoptions, ptrace_geteventmsg, WPTRACEEVENT,
        PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE,
        PTRACE_EVENT_EXEC)
    NEW_PROCESS_EVENT = (
        PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE)
if binding.HAS_PTRACE_GETREGS:
    from ptrace.binding import ptrace_getregs
else:
    from ptrace.binding import ptrace_peekuser, ptrace_registers_t
if disasm.HAS_DISASSEMBLER:
    from ptrace.disasm import disassemble, disassembleOne, MAX_INSTR_SIZE
if os_tools.HAS_PROC:
    from ptrace.linux_proc import readProcessStat

MIN_CODE_SIZE = 32
MAX_CODE_SIZE = 1024
DEFAULT_NB_INSTR = 10
DEFAULT_CODE_SIZE = 24


class PtraceProcess(object):
    """
    Process traced by a PtraceDebugger.

    Methods
    =======

     * control execution:

       - singleStep(): execute one instruction
       - cont(): continue the execution
       - syscall(): break at next syscall
       - setInstrPointer(): change the instruction pointer
       - os.kill(): send a signal to the process
       - terminate(): os.kill the process

     * wait an event:

      - waitEvent(): wait next process event
      - waitSignals(): wait a signal

     * get status

       - getreg(): get a register
       - getInstrPointer(): get the instruction pointer
       - getStackPointer(): get the stack pointer
       - getFramePointer(): get the stack pointer
       - getregs(): get all registers, e.g. regs=getregs(); print regs.eax
       - disassemble(): assembler code of the next instructions
       - disassembleOne(): assembler code of the next instruction
       - findStack(): get stack memory mapping
       - getsiginfo(): get signal information
       - getBacktrace(): get the current backtrace

     * set status

       - setreg(): set a register
       - setregs(): set all registers

     * memory access:

       - readWord(): read a memory word
       - readBytes(): read some bytes
       - readStruct(): read a structure
       - readArray(): read an array
       - readCString(): read a C string
       - readMappings(): get all memory mappings
       - writeWord(): write a memory word
       - writeBytes(): write some bytes

     * display status:

       - dumpCore(): display the next instructions
       - dumpStack(): display some memory words around the stack pointer
       - dumpMaps(): display memory mappings
       - dumpRegs(): display all registers

     * breakpoint:

       - createBreakpoint(): set a breakpoint
       - findBreakpoint(): find a breakpoint
       - removeBreakpoint(): remove a breakpoint

     * other:

       - setoptions(): set ptrace options

    See each method to get better documentation. You are responsible
    to manage the process state: some methods may fail or crash your
    processus if they are called when the process is in the wrong
    state.

    Attributes
    ==========

     * main attributes:
       - pid: identifier of the process
       - debugger: PtraceDebugger instance
       - breakpoints: dictionary of active breakpoints
       - parent: parent PtraceProcess (None if process has no parent)

     * state:
       - running: if True, the process is alive, otherwise the process
         doesn't exist anymore
       - exited: if True, the process has exited (attributed only used
         on BSD operation systems)
       - is_attached: if True, the process is attached by ptrace
       - was_attached: if True, the process will be detached at exit
       - is_stopped: if True, the process is stopped, otherwise it's
         running
       - syscall_state: control syscall tracing

    Sometimes, is_stopped value is wrong. You might use isTraced() to
    make sure that the process is stopped.
    """

    def __init__(self, debugger, pid, is_attached, parent=None, is_thread=False):
        self.debugger = debugger
        self.breakpoints = {}
        self.pid = pid
        self.running = True
        self.exited = False
        self.parent = parent
        self.was_attached = is_attached
        self.is_attached = False
        self.is_stopped = True
        self.is_thread = is_thread
        if not is_attached:
            self.attach()
        else:
            self.is_attached = True
        if os_tools.HAS_PROC:
            self.read_mem_file = None
        self.syscall_state = SyscallState(self)

    def isTraced(self):
        if not os_tools.HAS_PROC:
            self.notImplementedError()
        stat = readProcessStat(self.pid)
        return stat.state == 'T'

    def attach(self):
        if self.is_attached:
            return
        logging.info("Attach process %s" % self.pid)
        binding.ptrace_attach(self.pid)
        self.is_attached = True

    def dumpCode(self, start=None, stop=None, manage_bp=False, log=None):
        if not log:
            log = logging.error
        try:
            ip = self.getInstrPointer()
        except PtraceError as err:
            if start is None:
                log("Unable to read instruction pointer: %s" % err)
                return
            ip = None
        if start is None:
            start = ip

        try:
            self._dumpCode(start, stop, ip, manage_bp, log)
        except PtraceError as err:
            log("Unable to dump code at %s: %s" % (
                ctypes_tools.formatAddress(start), err))

    def _dumpCode(self, start, stop, ip, manage_bp, log):
        if stop is not None:
            stop = max(start, stop)
            stop = min(stop, start + MAX_CODE_SIZE - 1)

        if not disasm.HAS_DISASSEMBLER:
            if stop is not None:
                size = stop - start + 1
            else:
                size = MIN_CODE_SIZE
            code = self.readBytes(start, size)
            if os_tools.RUNNING_PYTHON3:
                text = " ".join("%02x" % byte for byte in code)
            else:
                text = " ".join("%02x" % ord(byte) for byte in code)
            log("CODE: %s" % text)
            return

        if manage_bp:
            address = start
            for _ in range(10):
                bp = False
                if address in self.breakpoints:
                    old_bytes = self.breakpoints[address].old_bytes
                    instr = disassembleOne(old_bytes, address)
                    bp = True
                else:
                    instr = self.disassembleOne(address)
                text = "%s| %s (%s)" % (ctypes_tools.formatAddress(
                    instr.address), instr.text, instr.hexa)
                if instr.address == ip:
                    text += " <=="
                if bp:
                    text += "     * BREAKPOINT *"
                log(text)
                address = address + instr.size
                if stop is not None and stop <= address:
                    break
        else:
            for instr in self.disassemble(start, stop):
                text = "%s| %s (%s)" % (ctypes_tools.formatAddress(
                    instr.address), instr.text, instr.hexa)
                if instr.address == ip:
                    text += " <=="
                log(text)

    def disassemble(self, start=None, stop=None, nb_instr=None):
        if not disasm.HAS_DISASSEMBLER:
            self.notImplementedError()
        if start is None:
            start = self.getInstrPointer()
        if stop is not None:
            stop = max(start, stop)
            size = stop - start + 1
        else:
            if nb_instr is None:
                nb_instr = DEFAULT_NB_INSTR
            size = nb_instr * MAX_INSTR_SIZE

        code = self.readBytes(start, size)
        for index, instr in enumerate(disassemble(code, start)):
            yield instr
            if nb_instr and nb_instr <= (index + 1):
                break

    def disassembleOne(self, address=None):
        if not disasm.HAS_DISASSEMBLER:
            self.notImplementedError()
        if address is None:
            address = self.getInstrPointer()
        code = self.readBytes(address, MAX_INSTR_SIZE)
        return disassembleOne(code, address)

    def findStack(self):
        for m in self.readMappings():
            if m.pathname == "[stack]":
                return m
        return None

    def detach(self):
        if not self.is_attached:
            return
        self.is_attached = False
        if self.running:
            logging.info("Detach %s" % self)
            binding.ptrace_detach(self.pid)
        self.debugger.deleteProcess(process=self)

    def _notRunning(self):
        self.running = False
        if os_tools.HAS_PROC and self.read_mem_file:
            try:
                self.read_mem_file.close()
            except IOError:
                pass
        self.detach()

    def kill(self, signum):
        os.kill(self.pid, signum)

    def terminate(self, wait_exit=True):
        if not self.running or not self.was_attached:
            return True
        logging.warning("Terminate %s" % self)
        done = False
        try:
            if self.is_stopped:
                self.cont(signal.SIGKILL)
            else:
                self.kill(signal.SIGKILL)
        except PtraceError as event:
            if event.errno == errno.ESRCH:
                done = True
            else:
                raise event
        if not done:
            if not wait_exit:
                return False
            self.waitExit()
        self._notRunning()
        return True

    def waitExit(self):
        while True:
            # Wait for any process signal
            event = self.waitEvent()
            event_cls = event.__class__

            # Process exited: we are done
            if event_cls == ProcessExit:
                return

            # Event different than a signal? Raise an exception
            if event_cls != ProcessSignal:
                raise event

            # Send the signal to the process
            signum = event.signum
            if signum not in (signal.SIGTRAP, signal.SIGSTOP):
                self.cont(signum)
            else:
                self.cont()

    def processStatus(self, status):
        # Process exited?
        if os.WIFEXITED(status):
            code = os.WEXITSTATUS(status)
            event = self.processExited(code)

        # Process os.killed by a signal?
        elif os.WIFSIGNALED(status):
            signum = os.WTERMSIG(status)
            event = self.processKilled(signum)

        # Invalid process status?
        elif not os.WIFSTOPPED(status):
            raise ProcessError(self, "Unknown process status: %r" % status)

        # Ptrace event?
        elif binding.HAS_PTRACE_EVENTS and WPTRACEEVENT(status):
            event = WPTRACEEVENT(status)
            event = self.ptraceEvent(event)

        else:
            signum = os.WSTOPSIG(status)
            event = self.processSignal(signum)
        return event

    def processTerminated(self):
        self._notRunning()
        return ProcessExit(self)

    def processExited(self, code):
        if os_tools.RUNNING_BSD and not self.exited:
            # on FreeBSD, we have to waitpid() twice
            # to avoid zombi process!?
            self.exited = True
            self.waitExit()
        self._notRunning()
        return ProcessExit(self, exitcode=code)

    def processKilled(self, signum):
        self._notRunning()
        return ProcessExit(self, signum=signum)

    def processSignal(self, signum):
        self.is_stopped = True
        return ProcessSignal(signum, self)

    def ptraceEvent(self, event):
        if not binding.HAS_PTRACE_EVENTS:
            self.notImplementedError()
        if event in NEW_PROCESS_EVENT:
            new_pid = ptrace_geteventmsg(self.pid)
            is_thread = (event == PTRACE_EVENT_CLONE)
            new_process = self.debugger.addProcess(
                new_pid, is_attached=True, parent=self, is_thread=is_thread)
            return NewProcessEvent(new_process)

        if event == PTRACE_EVENT_EXEC:
            return ProcessExecution(self)

        raise ProcessError(self, "Unknown ptrace event: %r" % event)

    def getregs(self):
        if binding.HAS_PTRACE_GETREGS:
            return ptrace_getregs(self.pid)

        # FIXME: Optimize getreg() when used with this function
        words = []
        nb_words = sizeof(ptrace_registers_t) // cpu_info.CPU_WORD_SIZE
        for offset in range(nb_words):
            word = ptrace_peekuser(self.pid,
                                   offset * cpu_info.CPU_WORD_SIZE)
            peeked_bytes = ctypes_tools.word2bytes(word)
            words.append(peeked_bytes)
        peeked_bytes = ''.join(words)
        return ctypes_tools.bytes2type(peeked_bytes, ptrace_registers_t)

    def getreg(self, name):
        try:
            name, shift, mask = cpu.CPU_SUB_REGISTERS[name]
        except KeyError:
            shift = 0
            mask = None
        if name not in binding.REGISTER_NAMES:
            raise ProcessError(self, "Unknown register: %r" % name)
        regs = self.getregs()
        value = getattr(regs, name)
        value >>= shift
        if mask:
            value &= mask
        return value

    def setregs(self, regs):
        binding.ptrace_setregs(self.pid, regs)

    def setreg(self, name, value):
        regs = self.getregs()
        if name in cpu.CPU_SUB_REGISTERS:
            full_name, shift, mask = cpu.CPU_SUB_REGISTERS[name]
            full_value = getattr(regs, full_name)
            full_value &= ~mask
            full_value |= ((value & mask) << shift)
            value = full_value
            name = full_name
        if name not in binding.REGISTER_NAMES:
            raise ProcessError(self, "Unknown register: %r" % name)
        setattr(regs, name, value)
        self.setregs(regs)

    def singleStep(self):
        if not binding.HAS_PTRACE_SINGLESTEP:
            self.notImplementedError()
        ptrace_singlestep(self.pid)

    def filterSignal(self, signum):
        # Never transfer signal.SIGTRAP signal
        return 0 if signum == signal.SIGTRAP else signum

    def syscall(self, signum=0):
        signum = self.filterSignal(signum)
        binding.ptrace_syscall(self.pid, signum)
        self.is_stopped = False

    def setInstrPointer(self, ip):
        if cpu.CPU_INSTR_POINTER:
            self.setreg(cpu.CPU_INSTR_POINTER, ip)
        else:
            raise ProcessError(
                self, "Instruction pointer register is not defined")

    def getInstrPointer(self):
        if cpu.CPU_INSTR_POINTER:
            return self.getreg(cpu.CPU_INSTR_POINTER)

        raise ProcessError(
            self, "Instruction pointer register is not defined")

    def getStackPointer(self):
        if cpu.CPU_STACK_POINTER:
            return self.getreg(cpu.CPU_STACK_POINTER)

        raise ProcessError(self, "Stack pointer register is not defined")

    def getFramePointer(self):
        if cpu.CPU_FRAME_POINTER:
            return self.getreg(cpu.CPU_FRAME_POINTER)

        raise ProcessError(self, "Stack pointer register is not defined")

    def _readBytes(self, address, size):
        offset = address % cpu_info.CPU_WORD_SIZE
        if offset:
            # Read word
            address -= offset
            word = self.readWord(address)
            word_bytes = ctypes_tools.word2bytes(word)

            # Read some bytes from the word
            subsize = min(cpu_info.CPU_WORD_SIZE - offset, size)
            data = word_bytes[offset:offset + subsize]  # FIXME: Big endian!

            # Move cursor
            size -= subsize
            address += cpu_info.CPU_WORD_SIZE
        else:
            data = b('')

        while size:
            # Read word
            word = self.readWord(address)
            word_bytes = ctypes_tools.word2bytes(word)

            # Read bytes from the word
            if size < cpu_info.CPU_WORD_SIZE:
                data += word_bytes[:size]   # <-- FIXME: Big endian!
                break
            data += word_bytes

            # Move cursor
            size -= cpu_info.CPU_WORD_SIZE
            address += cpu_info.CPU_WORD_SIZE
        return data

    def readWord(self, address):
        """Address have to be aligned!"""
        word = binding.ptrace_peektext(self.pid, address)
        return word

    if binding.HAS_PTRACE_IO:
        def readBytes(self, address, size):
            buffer = create_string_buffer(size)
            io_desc = ptrace_io_desc(
                piod_op=PIOD_READ_D,
                piod_offs=address,
                piod_addr=addressof(buffer),
                piod_len=size)
            ptrace_io(self.pid, io_desc)
            return buffer.raw
    elif os_tools.HAS_PROC:
        def readBytes(self, address, size):
            if not self.read_mem_file:
                filename = '/proc/%u/mem' % self.pid
                try:
                    self.read_mem_file = open(filename, 'rb', 0)
                except IOError as err:
                    message = ("Unable to open %s: fallback \
                        to ptrace implementation" % filename)
                    if err.errno != errno.EACCES:
                        logging.error(message)
                    else:
                        logging.info(message)
                    self.readBytes = self._readBytes
                    return self.readBytes(address, size)

            try:
                mem = self.read_mem_file
                mem.seek(address)
                data = mem.read(size)
            except (IOError, ValueError) as err:
                raise ProcessError(self, "readBytes(%s, %s) error: %s" % (
                    ctypes_tools.formatAddress(address), size, err))
            if not data and size:
                # Issue #10: If the process was not created by the debugger
                # (ex: fork), the kernel may deny reading private mappings of
                # /proc/pid/mem to the debugger, depending on the kernel
                # version and kernel config (ex: SELinux enabled or not).
                #
                # Fallback to PTRACE_PEEKTEXT. It is slower but a debugger
                # tracing the process is always allowed to use it.
                self.readBytes = self._readBytes
                return self.readBytes(address, size)
            return data
    else:
        readBytes = _readBytes

    def getsiginfo(self):
        if not binding.HAS_PTRACE_SIGINFO:
            self.notImplementedError()
        return ptrace_getsiginfo(self.pid)

    def writeBytes(self, address, src_bytes):
        if binding.HAS_PTRACE_IO:
            size = len(src_bytes)
            src_bytes = create_string_buffer(src_bytes)
            io_desc = ptrace_io_desc(
                piod_op=PIOD_WRITE_D,
                piod_offs=address,
                piod_addr=addressof(src_bytes),
                piod_len=size)
            ptrace_io(self.pid, io_desc)
        else:
            offset = address % cpu_info.CPU_WORD_SIZE
            if offset:
                # Write partial word (end)
                address -= offset
                size = cpu_info.CPU_WORD_SIZE - offset
                word = self.readBytes(address, cpu_info.CPU_WORD_SIZE)
                if len(src_bytes) < size:
                    size = len(src_bytes)
                    word = word[:offset] + src_bytes[:size] + \
                        word[offset + size:]  # <-- FIXME: Big endian!
                else:
                    # <-- FIXME: Big endian!
                    word = word[:offset] + src_bytes[:size]
                self.writeWord(address, ctypes_tools.bytes2word(word))
                src_bytes = src_bytes[size:]
                address += cpu_info.CPU_WORD_SIZE

            # Write full words
            while cpu_info.CPU_WORD_SIZE <= len(bytes):
                # Read one word
                word = src_bytes[:cpu_info.CPU_WORD_SIZE]
                word = ctypes_tools.bytes2word(word)
                self.writeWord(address, word)

                # Move to next word
                src_bytes = src_bytes[cpu_info.CPU_WORD_SIZE:]
                address += cpu_info.CPU_WORD_SIZE
            if not src_bytes:
                return

            # Write partial word (begin)
            size = len(src_bytes)
            word = self.readBytes(address, cpu_info.CPU_WORD_SIZE)
            # FIXME: Write big endian version of the next line
            word = src_bytes + word[size:]
            self.writeWord(address, ctypes_tools.bytes2word(word))

    def readStruct(self, address, struct):
        read_bytes = self.readBytes(address, sizeof(struct))
        read_bytes = c_char_p(read_bytes)
        return ctypes_tools.bytes2type(read_bytes, struct)

    def readArray(self, address, basetype, count):
        read_bytes = self.readBytes(address, sizeof(basetype) * count)
        read_bytes = c_char_p(read_bytes)
        return ctypes_tools.bytes2array(read_bytes, basetype, count)

    def readCString(self, address, max_size, chunk_length=256):
        string = []
        size = 0
        truncated = False
        while True:
            done = False
            data = self.readBytes(address, chunk_length)
            pos = data.find(b('\0'))
            if pos != -1:
                done = True
                data = data[:pos]
            if max_size <= size + chunk_length:
                data = data[:(max_size - size)]
                string.append(data)
                truncated = True
                break
            string.append(data)
            if done:
                break
            size += chunk_length
            address += chunk_length
        return b''.join(string), truncated

    def dumpStack(self, log=None):
        if not log:
            log = logging.error
        stack = self.findStack()
        if stack:
            log("STACK: %s" % stack)
        self._dumpStack(log)

    def _dumpStack(self, log):
        sp = self.getStackPointer()
        displayed = 0
        for index in range(-5, 5 + 1):
            delta = index * cpu_info.CPU_WORD_SIZE
            try:
                value = self.readWord(sp + delta)
                log("STACK%+ 3i: %s" % (delta, ctypes_tools.formatWordHex(value)))
                displayed += 1
            except PtraceError:
                pass
        if not displayed:
            log("ERROR: unable to read the stack (SP=%s)" % ctypes_tools.formatAddress(sp))

    def readMappings(self):
        return readProcessMappings(self)

    def dumpMaps(self, log=None):
        if not log:
            log = logging.error
        for m in self.readMappings():
            log("MAPS: %s" % m)

    def writeWord(self, address, word):
        """
        Address have to be aligned!
        """
        binding.ptrace_poketext(self.pid, address, word)

    def dumpRegs(self, log=None):
        if not log:
            log = logging.error
        try:
            regs = self.getregs()
            tools.dumpRegs(log, regs)
        except PtraceError as err:
            log("Unable to read registers: %s" % err)

    def cont(self, signum=0):
        signum = self.filterSignal(signum)
        binding.ptrace_cont(self.pid, signum)
        self.is_stopped = False

    def setoptions(self, options):
        if not binding.HAS_PTRACE_EVENTS:
            self.notImplementedError()
        logging.info("Set %s options to %s" % (self, options))
        ptrace_setoptions(self.pid, options)

    def waitEvent(self):
        return self.debugger.waitProcessEvent(pid=self.pid)

    def waitSignals(self, *signals):
        return self.debugger.waitSignals(*signals, **{'pid': self.pid})

    def waitSyscall(self):
        self.debugger.waitSyscall(self)

    def findBreakpoint(self, address):
        for bp in self.breakpoints.values():
            if bp.address <= address < bp.address + bp.size:
                return bp
        return None

    def createBreakpoint(self, address, size=1):
        bp = self.findBreakpoint(address)
        if bp:
            raise ProcessError(self, "A breakpoint is already set: %s" % bp)
        bp = Breakpoint(self, address, size)
        self.breakpoints[address] = bp
        return bp

    def getBacktrace(self, max_args=6, max_depth=20):
        return getBacktrace(self, max_args=max_args, max_depth=max_depth)

    def removeBreakpoint(self, bp):
        del self.breakpoints[bp.address]

    def __del__(self):
        try:
            self.detach()
        except PtraceError:
            pass

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<PtraceProcess #%s>" % self.pid

    def __hash__(self):
        return hash(self.pid)

    def notImplementedError(self):
        raise NotImplementedError()
