#!/usr/bin/env ruby
#
# DNSChecker made in the scope of some project
#
# Copyright (c) 2013 DNSChecker (www.enki-security.com - Y Kourosh BN)
#
# This program is the property of ENKI SECURITY - Kouros.Darius - Y BN.
# You may use it for free
#
# We provide ANY WARRANTY, ANY SUPPORT for a use which is not compliant to our policies

require 'prawn'
require 'date'
require 'rubygems'
require 'dnsruby'
include Dnsruby

require 'optparse'
require 'optparse/time'
require 'ostruct'

class Optcutit

 def self.parse(args)

	if __FILE__ == $0

	options = OpenStruct.new
	options.file = nil

	opts = OptionParser.new do |opts|
		script = File.basename($0)
		opts.banner = "Usage: ruby #{script} [options]"

		opts.separator ""

		opts.on("-f", "--file FILENAME", "Specify the zone file you want to test from") do |f|
			options.file = f
		end

		opts.on("-h", "--help", "Show this help message") { puts puts opts; exit }
		end

		opts.parse!(args)

		options
	end
 end
end

$opt = Optcutit.parse(ARGV)

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
	puts sio.read
	sio.rewind
	sio.read
end

#######
#### PDF Generation
###

def DNS_pdf_it()
        date = Date.today.to_s

        Prawn::Document.generate "DNSreport_#{date}.pdf" do
                font "Helvetica"
		repeat :all do
			bounding_box [bounds.left, bounds.top], :width  => bounds.width do
				y_position = cursor
				text "DNSChecker report", { :size => 18, :style => :bold }
				image 'logo.png', :scale => 0.6, :position => :right, :vposition => :top
				stroke_horizontal_rule
				move_down(3)
			end
		end

		pad 10 do
			text "<color rgb='683669'>List of checked domain name</color>", { :inline_format => true, :size => 16, :style => :bold }
		end

		if $opt.file != nil
			bounding_box([bounds.left, bounds.top - 60], :width  => bounds.width, :height => bounds.height - 100) do
			move_down(20)
				content_file = $opt.file
				File.open("#{content_file}", "r").each_line do |content|
					content = content.chomp
					text "#{content}"
				end
			end
				#{content_file}.close
		end

		bounding_box([bounds.left, bounds.top - 60], :width  => bounds.width, :height => bounds.height - 100) do
			dnscheck()
		end

		bounding_box [bounds.left, bounds.bottom + 20], :width  => bounds.width do
			repeat :all do
				stroke_horizontal_rule
				move_down(3)
				text "Confidential", { :size => 8, :style => :italic }
			end
			number_pages "<page>/<total>", { :start_count_at => 0, :page_filter => :all, :at => [bounds.right - 50, 0], :align => :right, :size => 8 }
		end
        end

        puts "Report DNSreport_#{date}.pdf was generated successfully"
        puts
end

#######
#### PDF line filling method
###

def pdf_liner(tgt, rec, resp, err)

	puts
	pdf_title1 = capture_stdout do
		puts "Results for #{tgt}"
	end

	pdf_title2 = capture_stdout do
		puts "'#{rec}' records queried"
	end

	move_down(5)
	text "#{pdf_title1}", {:size => 14, :style => :italic}
	text "#{pdf_title2}", {:size => 14, :style => :italic}
	move_down(5)

	puts

	if resp == nil
		pdf_dnschecked = capture_stdout do
			puts err
		end

		text "#{pdf_dnschecked}"
		move_down(15)

	else if resp.length > 0
		pdf_dnschecked = capture_stdout do
			puts resp
		end

		text "#{pdf_dnschecked}"
		move_down(15)

	else if resp.length == 0
		pdf_dnschecked = capture_stdout do
			puts "No #{rec} record found for #{tgt}"
		end

		text "#{pdf_dnschecked}"
		move_down(15)
	     end
	     end
	end
end

#######
#### DNSCheck method
###

def dnscheck()

	ans = "yes"
	zonefile = $opt.file

	if zonefile != nil
		puts
		puts "Processing #{zonefile}"
		puts "Please wait..."
		puts

		nameserv1 = "ns1.domain.com"
		nameserv2 = "ns2.domain.com"
		nameserv3 = "xxx.xx.xxx.xx"
		nameserv4 = "xxx.xxx.xx.x"

		enr = ["A", "NS", "MX", "CNAME", "PTR", "TXT"]

#		res1 = DNS.new({:nameserver => ["#{nameserv1}"]})
#		res2 = DNS.new({:nameserver => ["#{nameserv2}"]})
		res3 = DNS.new({:nameserver => ["#{nameserv3}"]})
		res4 = DNS.new({:nameserver => ["#{nameserv4}"]})

		tabserv = ["#{nameserv3}", "#{nameserv4}"]

		tabserv.each_with_index do |val, ind|
			start_new_page
			text "<color rgb='683669'>Test of #{tabserv[ind]} nameserver</color>", { :inline_format => true,
												:align => :center,
												:valign => :center,
												:size => 22,
												:style => :bold }
			File.open("#{zonefile}", "r").each_line do |tg_line|
				start_new_page
				enr.each do |item|
					tg_line = tg_line.chomp
					begin
#						*response1 = res1.getresources(#{tg_line}, #{item})
#						*response2 = res2.getresources("#{tg_line}", "#{item}")
						if "#{tabserv[ind]}" == "#{nameserv3}"
							*response3 = res3.getresources("#{tg_line}", "#{item}")
						else
							*response4 = res4.getresources("#{tg_line}", "#{item}")
						end
					rescue
						error = "Error occured when trying '#{item}' query for '#{tg_line}': Domain does not exist or SERVFAIL"
						puts
					end

#					pdf_liner(tg_line, record, response1, error)
#					pdf_liner(tg_line, enr, response2, error)
					if "#{tabserv[ind]}" == "#{nameserv3}"
						pdf_liner(tg_line, item, response3, error)
					else
						pdf_liner(tg_line, item, response4, error)
					end
				end
			end
		end

		outline.define do
			section 'Section 1', :destination => 1, :closed => true do           
				page :destination => 1, :title => 'Checked domain name'
			end
			section 'Section 2', :destination => 2, :closed => true do
				page :destination => 7, :title => 'ip or name test'
			end
			section 'Section 3', :destination => 3, :closed => true do
				page :destination => 247, :title => 'ip or name test'
			end
		end

		puts
		puts "process complete"
		puts

		#{zonefile}.close
	else
		while ans != "no"
			puts
			puts "Select the nameserver you want to test. Enter 1 or 2:"
			puts "1.	ns1.domain.com"
			puts "2.	ns2.domain.com"
			i = gets.chomp

			if i == "1" 
				nameserv = "ns1.domain.com"
			else
				nameserv = "xxx.xx.xxx.xx"
	#			nameserv = "ns2.domain.com"
			end

			puts
			puts "Enter the target you want to test"
			target = gets.chomp
			puts

			puts "Which type of record do you want to retreive?"
			puts "0.	A"
			puts "1.	NS"
			puts "2.	MX"
			puts "3.	CNAME"
			puts "4.	PTR"
			enr = gets.chomp
			puts

			res = DNS.new({:nameserver => ["#{nameserv}"]})
			res.do_caching = false

			case enr
				when '0'
					enr = 'A'
					begin
						*response = res.getresources("#{target}", "A")
					rescue
						error = "Error occured when trying '#{enr}' query for '#{target}': Domain does not exist or SERVFAIL"
						puts
					end

				when '1'
					enr = 'NS'
					begin
                        	                *response = res.getresources("#{target}", "NS")
       		                        rescue
                	                        error = "Error occured when trying '#{enr}' query for '#{target}': Domain does not exist or SERVFAIL"
						puts error
                                	        puts
                            		end
	
				when '2'
					enr = 'MX'
					begin
                        	                *response = res.getresources("#{target}", "MX")
                                	rescue
	                                        error = "Error occured when trying '#{enr}' query for '#{target}': Domain does not exist or SERVFAIL"
						puts error
                	                        puts
                        	        end

				when '3'
					enr = 'CNAME'
					begin
                        	                *response = res.getresources("#{target}", "CNAME")
                                	rescue
	                                        error = "Error occured when trying '#{enr}' query for '#{target}': Domain does not exist or SERVFAIL"
						puts error
                	                        puts
                        	        end

				when '4'
					enr = 'PTR'
					begin
                        	                *response = res.getresources("#{target}", "PTR")
	                                rescue
        	                                error = "Error occured when trying '#{enr}' query for '#{target}': Domain does not exist or SERVFAIL"
						puts error
                        	                puts
	                                end
	
				else
					puts "As required, please enter a number"
					enr = gets.chomp
					puts
			end

			pdf_liner(target, enr, response, error)
	
			puts
			puts "Do you want to continue checking? (answer yes/no)"
			ans = gets.chomp
			case ans
				when 'no'
					puts "Leaving..."
					break
				when 'yes'
					puts
				else
					puts
					puts "Invalid response"
					puts "Assuming you want to continue"
					puts
					ans = "yes"
			end
		end
	end
end

#######
#### Main program
###

DNS_pdf_it()
