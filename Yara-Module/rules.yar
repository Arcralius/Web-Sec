/*
Generated by Yara-Rules
On 12-04-2022
*/
include "./rules/antidebug_antivm.yar"
include "./rules/capabilities.yar"
include "./rules/crypto_signatures.yar"
include "./rules/CVE-2010-0805.yar"
include "./rules/CVE-2010-0887.yar"
include "./rules/CVE-2010-1297.yar"
include "./rules/CVE-2012-0158.yar"
include "./rules/CVE-2013-0074.yar"
include "./rules/CVE-2013-0422.yar"
include "./rules/CVE-2015-1701.yar"
include "./rules/CVE-2015-2426.yar"
include "./rules/CVE-2015-2545.yar"
include "./rules/CVE-2015-5119.yar"
include "./rules/CVE-2016-5195.yar"
include "./rules/CVE-2017-11882.yar"
include "./rules/CVE-2018-20250.yar"
include "./rules/CVE-2018-4878.yar"
include "./rules/EMAIL_Cryptowall.yar"
include "./rules/Email_PHP_Mailer.yar"
include "./rules/Email_fake_it_maintenance_bulletin.yar"
include "./rules/Email_generic_phishing.yar"
include "./rules/Email_quota_limit_warning.yar"
include "./rules/attachment.yar"
include "./rules/email_Ukraine_BE_powerattack.yar"
include "./rules/extortion_email.yar"
include "./rules/image.yar"
include "./rules/scam.yar"
include "./rules/urls.yar"
include "./rules/EK_Angler.yar"
include "./rules/EK_Blackhole.yar"
include "./rules/EK_BleedingLife.yar"
include "./rules/EK_Crimepack.yar"
include "./rules/EK_Eleonore.yar"
include "./rules/EK_Fragus.yar"
include "./rules/EK_Phoenix.yar"
include "./rules/EK_Sakura.yar"
include "./rules/EK_ZeroAcces.yar"
include "./rules/EK_Zerox88.yar"
include "./rules/EK_Zeus.yar"
include "./rules/Maldoc_APT10_MenuPass.yar"
include "./rules/Maldoc_APT19_CVE-2017-0199.yar"
include "./rules/Maldoc_APT_OLE_JSRat.yar"
include "./rules/Maldoc_CVE-2017-0199.yar"
include "./rules/Maldoc_CVE_2017_11882.yar"
include "./rules/Maldoc_CVE_2017_8759.yar"
include "./rules/Maldoc_Contains_VBE_File.yar"
include "./rules/Maldoc_DDE.yar"
include "./rules/Maldoc_Dridex.yar"
include "./rules/Maldoc_Hidden_PE_file.yar"
include "./rules/Maldoc_MIME_ActiveMime_b64.yar"
include "./rules/Maldoc_PDF.yar"
include "./rules/Maldoc_PowerPointMouse.yar"
include "./rules/Maldoc_Suspicious_OLE_target.yar"
include "./rules/Maldoc_UserForm.yar"
include "./rules/Maldoc_VBA_macro_code.yar"
include "./rules/Maldoc_Word_2007_XML_Flat_OPC.yar"
include "./rules/Maldoc_hancitor_dropper.yar"
include "./rules/Maldoc_malrtf_ole2link.yar"
include "./rules/maldoc_somerules.yar"
include "./rules/000_common_rules.yar"
include "./rules/APT_APT1.yar"
include "./rules/APT_APT10.yar"
include "./rules/APT_APT15.yar"
include "./rules/APT_APT17.yar"
include "./rules/APT_APT29_Grizzly_Steppe.yar"
include "./rules/APT_APT3102.yar"
include "./rules/APT_APT9002.yar"
include "./rules/APT_Backspace.yar"
include "./rules/APT_Bestia.yar"
include "./rules/APT_Blackenergy.yar"
include "./rules/APT_Bluetermite_Emdivi.yar"
include "./rules/APT_C16.yar"
include "./rules/APT_Carbanak.yar"
include "./rules/APT_Careto.yar"
include "./rules/APT_Casper.yar"
include "./rules/APT_CheshireCat.yar"
include "./rules/APT_Cloudduke.yar"
include "./rules/APT_Cobalt.yar"
include "./rules/APT_Codoso.yar"
include "./rules/APT_CrashOverride.yar"
include "./rules/APT_DPRK_ROKRAT.yar"
include "./rules/APT_DeepPanda_Anthem.yar"
include "./rules/APT_DeputyDog.yar"
include "./rules/APT_Derusbi.yar"
include "./rules/APT_Dubnium.yar"
include "./rules/APT_Duqu2.yar"
include "./rules/APT_EQUATIONGRP.yar"
include "./rules/APT_Emissary.yar"
include "./rules/APT_EnergeticBear_backdoored_ssh.yar"
include "./rules/APT_Equation.yar"
include "./rules/APT_FVEY_ShadowBrokers_Jan17_Screen_Strings.yar"
include "./rules/APT_FiveEyes.yar"
include "./rules/APT_Grasshopper.yar"
include "./rules/APT_Greenbug.yar"
include "./rules/APT_Grizzlybear_uscert.yar"
include "./rules/APT_HackingTeam.yar"
include "./rules/APT_Hellsing.yar"
include "./rules/APT_HiddenCobra.yar"
include "./rules/APT_Hikit.yar"
include "./rules/APT_Industroyer.yar"
include "./rules/APT_Irontiger.yar"
include "./rules/APT_Kaba.yar"
include "./rules/APT_Ke3Chang_TidePool.yar"
include "./rules/APT_KeyBoy.yar"
include "./rules/APT_LotusBlossom.yar"
include "./rules/APT_Minidionis.yar"
include "./rules/APT_Mirage.yar"
include "./rules/APT_Molerats.yar"
include "./rules/APT_Mongall.yar"
include "./rules/APT_MoonlightMaze.yar"
include "./rules/APT_NGO.yar"
include "./rules/APT_OPCleaver.yar"
include "./rules/APT_Oilrig.yar"
include "./rules/APT_OpClandestineWolf.yar"
include "./rules/APT_OpDustStorm.yar"
include "./rules/APT_OpPotao.yar"
include "./rules/APT_PCclient.yar"
include "./rules/APT_Passcv.yar"
include "./rules/APT_Pipcreat.yar"
include "./rules/APT_Platinum.yar"
include "./rules/APT_Poseidon_Group.yar"
include "./rules/APT_Prikormka.yar"
include "./rules/APT_PutterPanda.yar"
include "./rules/APT_RedLeaves.yar"
include "./rules/APT_Regin.yar"
include "./rules/APT_RemSec.yar"
include "./rules/APT_Sauron.yar"
include "./rules/APT_Sauron_extras.yar"
include "./rules/APT_Scarab_Scieron.yar"
include "./rules/APT_Seaduke.yar"
include "./rules/APT_Shamoon_StoneDrill.yar"
include "./rules/APT_Snowglobe_Babar.yar"
include "./rules/APT_Sofacy_Bundestag.yar"
include "./rules/APT_Sofacy_Fysbis.yar"
include "./rules/APT_Sofacy_Jun16.yar"
include "./rules/APT_Sphinx_Moth.yar"
include "./rules/APT_Stuxnet.yar"
include "./rules/APT_Terracota.yar"
include "./rules/APT_ThreatGroup3390.yar"
include "./rules/APT_TradeSecret.yar"
include "./rules/APT_Turla_Neuron.yar"
include "./rules/APT_Turla_RUAG.yar"
include "./rules/APT_UP007_SLServer.yar"
include "./rules/APT_Unit78020.yar"
include "./rules/APT_Uppercut.yar"
include "./rules/APT_Waterbug.yar"
include "./rules/APT_WildNeutron.yar"
include "./rules/APT_Windigo_Onimiki.yar"
include "./rules/APT_Winnti.yar"
include "./rules/APT_WoolenGoldfish.yar"
include "./rules/APT_eqgrp_apr17.yar"
include "./rules/APT_fancybear_dnc.yar"
include "./rules/APT_fancybear_downdelph.yar"
include "./rules/APT_furtim.yar"
include "./rules/EXPERIMENTAL_Beef.yar"
include "./rules/GEN_PowerShell.yar"
include "./rules/MALW_ATMPot.yar"
include "./rules/MALW_ATM_HelloWorld.yar"
include "./rules/MALW_AZORULT.yar"
include "./rules/MALW_AgentTesla.yar"
include "./rules/MALW_AgentTesla_SMTP.yar"
include "./rules/MALW_AlMashreq.yar"
include "./rules/MALW_Alina.yar"
include "./rules/MALW_Andromeda.yar"
include "./rules/MALW_Arkei.yar"
include "./rules/MALW_Athena.yar"
include "./rules/MALW_Atmos.yar"
include "./rules/MALW_BackdoorSSH.yar"
include "./rules/MALW_Backoff.yar"
include "./rules/MALW_Bangat.yar"
include "./rules/MALW_Batel.yar"
include "./rules/MALW_BlackRev.yar"
include "./rules/MALW_BlackWorm.yar"
include "./rules/MALW_Boouset.yar"
include "./rules/MALW_Bublik.yar"
include "./rules/MALW_Buzus_Softpulse.yar"
include "./rules/MALW_CAP_HookExKeylogger.yar"
include "./rules/MALW_Chicken.yar"
include "./rules/MALW_Citadel.yar"
include "./rules/MALW_Cloaking.yar"
include "./rules/MALW_Cookies.yar"
include "./rules/MALW_Corkow.yar"
include "./rules/MALW_Cxpid.yar"
include "./rules/MALW_Cythosia.yar"
include "./rules/MALW_DDoSTf.yar"
include "./rules/MALW_Derkziel.yar"
include "./rules/MALW_Dexter.yar"
include "./rules/MALW_DiamondFox.yar"
include "./rules/MALW_DirtJumper.yar"
include "./rules/MALW_Eicar.yar"
include "./rules/MALW_Elex.yar"
include "./rules/MALW_Elknot.yar"
include "./rules/MALW_Emotet.yar"
include "./rules/MALW_Empire.yar"
include "./rules/MALW_Enfal.yar"
include "./rules/MALW_Exploit_UAC_Elevators.yar"
include "./rules/MALW_Ezcob.yar"
include "./rules/MALW_F0xy.yar"
include "./rules/MALW_FALLCHILL.yar"
include "./rules/MALW_FUDCrypt.yar"
include "./rules/MALW_FakeM.yar"
include "./rules/MALW_Fareit.yar"
include "./rules/MALW_Favorite.yar"
include "./rules/MALW_Furtim.yar"
include "./rules/MALW_Gafgyt.yar"
include "./rules/MALW_Genome.yar"
include "./rules/MALW_Glasses.yar"
include "./rules/MALW_Gozi.yar"
include "./rules/MALW_Grozlex.yar"
include "./rules/MALW_Hajime.yar"
include "./rules/MALW_Hsdfihdf_banking.yar"
include "./rules/MALW_Httpsd_ELF.yar"
include "./rules/MALW_IMuler.yar"
include "./rules/MALW_IcedID.yar"
include "./rules/MALW_Iexpl0ree.yar"
include "./rules/MALW_Install11.yar"
include "./rules/MALW_Intel_Virtualization.yar"
include "./rules/MALW_IotReaper.yar"
include "./rules/MALW_Jolob_Backdoor.yar"
include "./rules/MALW_KINS.yar"
include "./rules/MALW_Kelihos.yar"
include "./rules/MALW_KeyBase.yar"
include "./rules/MALW_Korlia.yar"
include "./rules/MALW_Korplug.yar"
include "./rules/MALW_Kovter.yar"
include "./rules/MALW_Kraken.yar"
include "./rules/MALW_Kwampirs.yar"
include "./rules/MALW_LURK0.yar"
include "./rules/MALW_Lateral_Movement.yar"
include "./rules/MALW_Lenovo_Superfish.yar"
include "./rules/MALW_LinuxBew.yar"
include "./rules/MALW_LinuxHelios.yar"
include "./rules/MALW_LinuxMoose.yar"
include "./rules/MALW_LostDoor.yar"
include "./rules/MALW_LuaBot.yar"
include "./rules/MALW_LuckyCat.yar"
include "./rules/MALW_MSILStealer.yar"
include "./rules/MALW_MacControl.yar"
include "./rules/MALW_MacGyver.yar"
include "./rules/MALW_Madness.yar"
include "./rules/MALW_Magento_backend.yar"
include "./rules/MALW_Magento_frontend.yar"
include "./rules/MALW_Magento_suspicious.yar"
include "./rules/MALW_Mailers.yar"
include "./rules/MALW_MedusaHTTP_2019.yar"
include "./rules/MALW_Miancha.yar"
include "./rules/MALW_MiniAsp3_mem.yar"
include "./rules/MALW_Mirai.yar"
include "./rules/MALW_Mirai_Okiru_ELF.yar"
include "./rules/MALW_Mirai_Satori_ELF.yar"
include "./rules/MALW_Miscelanea.yar"
include "./rules/MALW_Miscelanea_Linux.yar"
include "./rules/MALW_Monero_Miner_installer.yar"
include "./rules/MALW_NSFree.yar"
include "./rules/MALW_Naikon.yar"
include "./rules/MALW_Naspyupdate.yar"
include "./rules/MALW_NetTraveler.yar"
include "./rules/MALW_NionSpy.yar"
include "./rules/MALW_Notepad.yar"
include "./rules/MALW_OSX_Leverage.yar"
include "./rules/MALW_Odinaff.yar"
include "./rules/MALW_Olyx.yar"
include "./rules/MALW_PE_sections.yar"
include "./rules/MALW_PittyTiger.yar"
include "./rules/MALW_PolishBankRat.yar"
include "./rules/MALW_Ponmocup.yar"
include "./rules/MALW_Pony.yar"
include "./rules/MALW_Predator.yar"
include "./rules/MALW_PubSab.yar"
include "./rules/MALW_PurpleWave.yar"
include "./rules/MALW_PyPI.yar"
include "./rules/MALW_Pyinstaller.yar"
include "./rules/MALW_Pyinstaller_OSX.yar"
include "./rules/MALW_Quarian.yar"
include "./rules/MALW_Rebirth_Vulcan_ELF.yar"
include "./rules/MALW_Regsubdat.yar"
include "./rules/MALW_Rockloader.yar"
include "./rules/MALW_Rooter.yar"
include "./rules/MALW_Rovnix.yar"
include "./rules/MALW_Safenet.yar"
include "./rules/MALW_Sakurel.yar"
include "./rules/MALW_Sayad.yar"
include "./rules/MALW_Scarhikn.yar"
include "./rules/MALW_Sendsafe.yar"
include "./rules/MALW_Shamoon.yar"
include "./rules/MALW_Shifu.yar"
include "./rules/MALW_Skeleton.yar"
include "./rules/MALW_Spora.yar"
include "./rules/MALW_Sqlite.yar"
include "./rules/MALW_Stealer.yar"
include "./rules/MALW_Surtr.yar"
include "./rules/MALW_T5000.yar"
include "./rules/MALW_TRITON_HATMAN.yar"
include "./rules/MALW_TRITON_ICS_FRAMEWORK.yar"
include "./rules/MALW_Tedroo.yar"
include "./rules/MALW_Tinba.yar"
include "./rules/MALW_TinyShell_Backdoor_gen.yar"
include "./rules/MALW_Torte_ELF.yar"
include "./rules/MALW_TreasureHunt.yar"
include "./rules/MALW_TrickBot.yar"
include "./rules/MALW_Trumpbot.yar"
include "./rules/MALW_Upatre.yar"
include "./rules/MALW_Urausy.yar"
include "./rules/MALW_Vidgrab.yar"
include "./rules/MALW_Virut_FileInfector_UNK_VERSION.yar"
include "./rules/MALW_Volgmer.yar"
include "./rules/MALW_Wabot.yar"
include "./rules/MALW_Warp.yar"
include "./rules/MALW_Wimmie.yar"
include "./rules/MALW_XHide.yar"
include "./rules/MALW_XMRIG_Miner.yar"
include "./rules/MALW_XOR_DDos.yar"
include "./rules/MALW_Yayih.yar"
include "./rules/MALW_Yordanyan_ActiveAgent.yar"
include "./rules/MALW_Zegost.yar"
include "./rules/MALW_Zeus.yar"
include "./rules/MALW_adwind_RAT.yar"
include "./rules/MALW_hancitor.yar"
include "./rules/MALW_kirbi_mimikatz.yar"
include "./rules/MALW_kpot.yar"
include "./rules/MALW_marap.yar"
include "./rules/MALW_shifu_shiz.yar"
include "./rules/MALW_sitrof_fortis_scar.yar"
include "./rules/MALW_viotto_keylogger.yar"
include "./rules/MALW_xDedic_marketplace.yar"
include "./rules/MalConfScan.yar"
include "./rules/Operation_Blockbuster/DeltaCharlie.yara"
include "./rules/Operation_Blockbuster/HotelAlfa.yara"
include "./rules/Operation_Blockbuster/IndiaAlfa.yara"
include "./rules/Operation_Blockbuster/IndiaBravo.yara"
include "./rules/Operation_Blockbuster/IndiaCharlie.yara"
include "./rules/Operation_Blockbuster/IndiaDelta.yara"
include "./rules/Operation_Blockbuster/IndiaEcho.yara"
include "./rules/Operation_Blockbuster/IndiaGolf.yara"
include "./rules/Operation_Blockbuster/IndiaHotel.yara"
include "./rules/Operation_Blockbuster/IndiaJuliett.yara"
include "./rules/Operation_Blockbuster/IndiaWhiskey.yara"
include "./rules/Operation_Blockbuster/KiloAlfa.yara"
include "./rules/Operation_Blockbuster/LimaAlfa.yara"
include "./rules/Operation_Blockbuster/LimaBravo.yara"
include "./rules/Operation_Blockbuster/LimaCharlie.yara"
include "./rules/Operation_Blockbuster/LimaDelta.yara"
include "./rules/Operation_Blockbuster/PapaAlfa.yara"
include "./rules/Operation_Blockbuster/RomeoAlfa.yara"
include "./rules/Operation_Blockbuster/RomeoBravo.yara"
include "./rules/Operation_Blockbuster/RomeoCharlie.yara"
include "./rules/Operation_Blockbuster/RomeoDelta.yara"
include "./rules/Operation_Blockbuster/RomeoEcho.yara"
include "./rules/Operation_Blockbuster/RomeoFoxtrot_mod.yara"
include "./rules/Operation_Blockbuster/RomeoGolf_mod.yara"
include "./rules/Operation_Blockbuster/RomeoHotel.yara"
include "./rules/Operation_Blockbuster/RomeoWhiskey.yara"
include "./rules/Operation_Blockbuster/SierraAlfa.yara"
include "./rules/Operation_Blockbuster/SierraBravo.yara"
include "./rules/Operation_Blockbuster/SierraCharlie.yara"
include "./rules/Operation_Blockbuster/SierraJuliettMikeOne.yara"
include "./rules/Operation_Blockbuster/SierraJuliettMikeTwo.yara"
include "./rules/Operation_Blockbuster/TangoAlfa.yara"
include "./rules/Operation_Blockbuster/TangoBravo.yara"
include "./rules/Operation_Blockbuster/UniformAlfa.yara"
include "./rules/Operation_Blockbuster/UniformJuliett.yara"
include "./rules/Operation_Blockbuster/WhiskeyAlfa.yara"
include "./rules/Operation_Blockbuster/WhiskeyBravo_mod.yara"
include "./rules/Operation_Blockbuster/WhiskeyCharlie.yara"
include "./rules/Operation_Blockbuster/WhiskeyDelta.yara"
include "./rules/Operation_Blockbuster/cert_wiper.yara"
include "./rules/Operation_Blockbuster/general.yara"
include "./rules/Operation_Blockbuster/sharedcode.yara"
include "./rules/Operation_Blockbuster/suicidescripts.yara"
include "./rules/POS.yar"
include "./rules/POS_Bernhard.yar"
include "./rules/POS_BruteforcingBot.yar"
include "./rules/POS_Easterjack.yar"
include "./rules/POS_FastPOS.yar"
include "./rules/POS_LogPOS.yar"
include "./rules/POS_MalumPOS.yar"
include "./rules/POS_Mozart.yar"
include "./rules/RANSOM_.CRYPTXXX.yar"
include "./rules/RANSOM_777.yar"
include "./rules/RANSOM_Alpha.yar"
include "./rules/RANSOM_BadRabbit.yar"
include "./rules/RANSOM_Cerber.yar"
include "./rules/RANSOM_Comodosec.yar"
include "./rules/RANSOM_Crypren.yar"
include "./rules/RANSOM_CryptoNar.yar"
include "./rules/RANSOM_Cryptolocker.yar"
include "./rules/RANSOM_DMALocker.yar"
include "./rules/RANSOM_DoublePulsar_Petya.yar"
include "./rules/RANSOM_Erebus.yar"
include "./rules/RANSOM_GPGQwerty.yar"
include "./rules/RANSOM_GoldenEye.yar"
include "./rules/RANSOM_Locky.yar"
include "./rules/RANSOM_MS17-010_Wannacrypt.yar"
include "./rules/RANSOM_Maze.yar"
include "./rules/RANSOM_PetrWrap.yar"
include "./rules/RANSOM_Petya.yar"
include "./rules/RANSOM_Petya_MS17_010.yar"
include "./rules/RANSOM_Pico.yar"
include "./rules/RANSOM_Revix.yar"
include "./rules/RANSOM_SamSam.yar"
include "./rules/RANSOM_Satana.yar"
include "./rules/RANSOM_Shiva.yar"
include "./rules/RANSOM_Sigma.yar"
include "./rules/RANSOM_Snake.yar"
include "./rules/RANSOM_Stampado.yar"
include "./rules/RANSOM_TeslaCrypt.yar"
include "./rules/RANSOM_Tox.yar"
include "./rules/RANSOM_acroware.yar"
include "./rules/RANSOM_jeff_dev.yar"
include "./rules/RANSOM_locdoor.yar"
include "./rules/RANSOM_screenlocker_5h311_1nj3c706.yar"
include "./rules/RANSOM_shrug2.yar"
include "./rules/RANSOM_termite.yar"
include "./rules/RAT_Adwind.yar"
include "./rules/RAT_Adzok.yar"
include "./rules/RAT_Asyncrat.yar"
include "./rules/RAT_BlackShades.yar"
include "./rules/RAT_Bolonyokte.yar"
include "./rules/RAT_Bozok.yar"
include "./rules/RAT_Cerberus.yar"
include "./rules/RAT_Crimson.yar"
include "./rules/RAT_CrossRAT.yar"
include "./rules/RAT_CyberGate.yar"
include "./rules/RAT_DarkComet.yar"
include "./rules/RAT_FlyingKitten.yar"
include "./rules/RAT_Gh0st.yar"
include "./rules/RAT_Gholee.yar"
include "./rules/RAT_Glass.yar"
include "./rules/RAT_Havex.yar"
include "./rules/RAT_Hizor.yar"
include "./rules/RAT_Indetectables.yar"
include "./rules/RAT_Inocnation.yar"
include "./rules/RAT_Meterpreter_Reverse_Tcp.yar"
include "./rules/RAT_Nanocore.yar"
include "./rules/RAT_NetwiredRC.yar"
include "./rules/RAT_Njrat.yar"
include "./rules/RAT_Orcus.yar"
include "./rules/RAT_PlugX.yar"
include "./rules/RAT_PoetRATDoc.yar"
include "./rules/RAT_PoetRATPython.yar"
include "./rules/RAT_PoisonIvy.yar"
include "./rules/RAT_Ratdecoders.yar"
include "./rules/RAT_Sakula.yar"
include "./rules/RAT_ShadowTech.yar"
include "./rules/RAT_Shim.yar"
include "./rules/RAT_Terminator.yar"
include "./rules/RAT_Xtreme.yar"
include "./rules/RAT_ZoxPNG.yar"
include "./rules/RAT_jRAT.yar"
include "./rules/RAT_xRAT.yar"
include "./rules/RAT_xRAT20.yar"
include "./rules/TOOLKIT_Chinese_Hacktools.yar"
include "./rules/TOOLKIT_Dubrute.yar"
include "./rules/TOOLKIT_FinFisher_.yar"
include "./rules/TOOLKIT_Gen_powerkatz.yar"
include "./rules/TOOLKIT_Mandibule.yar"
include "./rules/TOOLKIT_PassTheHash.yar"
include "./rules/TOOLKIT_Powerstager.yar"
include "./rules/TOOLKIT_Pwdump.yar"
include "./rules/TOOLKIT_Redteam_Tools_by_GUID.yar"
include "./rules/TOOLKIT_Redteam_Tools_by_Name.yar"
include "./rules/TOOLKIT_Solarwinds_credential_stealer.yar"
include "./rules/TOOLKIT_THOR_HackTools.yar"
include "./rules/TOOLKIT_Wineggdrop.yar"
include "./rules/TOOLKIT_exe2hex_payload.yar"
include "./rules/JJencode.yar"
include "./rules/Javascript_exploit_and_obfuscation.yar"
include "./rules/packer.yar"
include "./rules/packer_compiler_signatures.yar"
include "./rules/peid.yar"
include "./rules/tweetable-polyglot-png.yar"
include "./rules/WShell_APT_Laudanum.yar"
include "./rules/WShell_ASPXSpy.yar"
include "./rules/WShell_ChinaChopper.yar"
include "./rules/WShell_Drupalgeddon2_icos.yar"
include "./rules/WShell_PHP_Anuna.yar"
include "./rules/WShell_PHP_in_images.yar"
include "./rules/WShell_THOR_Webshells.yar"
include "./rules/Wshell_ChineseSpam.yar"
include "./rules/Wshell_fire2013.yar"
include "./rules/node_opensl_1_0_1.yara"
include "./rules/nodemailer_js_4_0_1.yara"
include "./rules/opencv_js_1_0_1.yara"
include "./rules/noderequest_2_81_0.yara"
include "./rules/nodemssql_4_0_5.yara"
include "./rules/mssql_js_4_0_5.yara"
include "./rules/mysqljs_2_13_0.yara"
include "./rules/nodesqlite_2_8_1.yara"
include "./rules/node_tkinter_1_0_1.yara"
include "./rules/babelcli_1_0_1.yara"
include "./rules/cross_env_js_5_0_1.yara"
include "./rules/mssql_node_4_0_5.yara"
include "./rules/sqlserver_4_0_5.yara"
include "./rules/openssl_js_1_0_1.yara"
include "./rules/http_proxy_js_0_11_3.yara"
include "./rules/nodecaffe_0_0_1.yara"
include "./rules/crossenv_6_1_1.yara"
include "./rules/node_sqlite_2_8_1.yara"
include "./rules/shadowsock_2_0_1.yara"
include "./rules/node_openssl_1_0_1.yara"
include "./rules/tkinter_1_0_1.yara"
include "./rules/node_opencv_1_0_1.yara"
include "./rules/nodesass_4_5_3.yara"
include "./rules/mongose_4_11_3.yara"
include "./rules/sqlite_js_2_8_1.yara"
include "./rules/mariadb_2_13_0.yara"
include "./rules/ffmepg_0_0_1.yara"
include "./rules/sqliter_2_8_1.yara"
include "./rules/nodefabric_1_7_18.yara"
include "./rules/smb_1_5_1.yara"
include "./rules/fabric_js_1_7_18.yara"
include "./rules/d3_js_1_0_1.yara"
include "./rules/gruntcli_1_0_1.yara"
include "./rules/nodeffmpeg_0_0_1.yara"
include "./rules/node_fabric_1_7_18.yara"
include "./rules/proxy_js_0_11_3.yara"
include "./rules/jquery_js_3_2_2.yara"
include "./rules/detect_discord_token_stealer.yara"
include "./rules/detect_environment_variable_stealer.yara"

