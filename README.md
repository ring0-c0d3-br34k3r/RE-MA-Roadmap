# RE-MA-Roadmap
# Reverse Engineering and Malware Analysis Roadmap
![image](https://github.com/user-attachments/assets/7b005164-804f-4d3f-a5d9-ef055cb9590e)

Welcome to the comprehensive roadmap for mastering reverse engineering and malware analysis. This roadmap is designed to guide individuals from beginner to expert level in the field of reverse engineering and malware analysis.

## Foundations
### 0x00 Establishing a Secure Lab Environment
- [Reverse Engineering For Everyone!](https://0xinfection.github.io/reversing/)
- [Malware Analysis Virtual Machine – by OALabs](https://www.youtube.com/watch?v=ql9D5MuK_3c)
- [Creating a Simple Free Malware Analysis Environment – by MalwareTech](https://www.malwaretech.com/beginner-malware-reversing-challenges)

### 0x01 Mastering Reverse Engineering Tools
- [Reversing with Lena151  – learn OllyDbg (old, but still very useful)](https://github.com/kosmokato/Lena151)
- [REVERSING WITH IDA PRO FROM SCRATCH](http://ricardonarvaja.info/WEB/IDA%20DESDE%20CERO/EN%20INGLES/INGLES/)
- [Introduction to Windbg and debugging windows](https://www.youtube.com/playlist?list=PLhx7-txsG6t6n_E2LgDGqgvJtCHPL7UFu)

## Gathering Intelligence
### 0x02 Sourcing Malware Samples
- [MalwareBreakdown](https://malwarebreakdown.com/)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [VX Underground](https://vx-underground.org/samples.html)
- [Malshare](http://www.malshare.com/)
- [VirusShare](https://virusshare.com/)
- [Abuse.ch](https://bazaar.abuse.ch/)
- [TheZoo](http://thezoo.morirt.com/)
- [VirusBay](https://beta.virusbay.io/)

### 0x03 Gathering Threat Intelligence
- [Benkow](http://benkow.cc)
- [VXVault](http://vxvault.net/)
- [Cybercrime Tracker](http://cybercrime-tracker.net/)

## Analyzing Malware Families
### 0x04 Understanding Common Malware Families
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)

## Practical Exercises
### 0x05 Beginner Challenges and Writeups
- [Beginner Malware Reversing Challenges (by Malware Tech)](https://github.com/MalwareTech/Beginner-Reversing-Challenges)
- [solve the Malwarebytes CrackMe: a step-by-step tutorial](https://www.malwarebytes.com/blog/news/2017/11/how-to-solve-the-malwarebytes-crackme-a-step-by-step-tutorial)
- [MalwareTech Windows Reversing Challenge #1 Write-Ups](https://irfanalditya.github.io/posts/malwaretech-chal1/)
- [MalwareTech Windows Reversing Challenge #2 Write-Ups](https://irfanalditya.github.io/posts/malwaretech-chal2/)
- [MalwareTech Windows Reversing Challenge #3 Write-Ups](https://irfanalditya.github.io/posts/malwaretech-chal3/)
- [Crackmes.one – various crackmes to help you exercise reversing](https://crackmes.one/)
- ["Nightmare" – a reverse engineering course created around CTF tasks](https://github.com/guyinatuxedo/nightmare)
- [FlareOn Challenge writeups](https://github.com/fareedfauzi/Flare-On-Challenges)

## Understanding Low-Level Concepts
### 0x06 Assembly Language and PE Format
- [Video 1](https://www.youtube.com/watch?v=wLXIWKUWpSs&pp=ygUaIHg4NiBhc3NlbWJseSBpbnRyb2R1Y3Rpb24%3D) and [Video 2](https://www.youtube.com/watch?v=cFGJhn97e3s) for x86 assembly introduction
- Free course on assembly for other platforms
- Intel official manual on assembly language
- [An In-Depth Look Into The Win32 Portable Executable File Format](https://www.scribd.com/document/607827843/An-In-Depth-Look-into-the-Win32-Portable-Executable-File-Format)
- [An In-Depth Look into the Win32 Portable Executable File Format](https://mcsi-library.readthedocs.io/articles/2022/05/reverse-engineering-portable-executables-pe-part-2/reverse-engineering-portable-executables-pe-part-2.html)
- [Peering Inside the PE: A Tour of the Win32 Portable Executable File Format](https://coffi.readthedocs.io/en/latest/peering_inside_pe.pdf)
- [PE101](https://github.com/corkami/pics/tree/master/binary/pe101) and [PE102](https://github.com/corkami/pics/tree/master/binary/pe102) by Ange Albertini

### 0x07 Programming for Reverse Engineering
- C/C++, Python, and Assembly
- [MalwareTech's article on programming for malware analysis](https://www.malwaretech.com/2018/03/best-programming-languages-to-learn-for-malware-analysis.html)
- Recommended learning resources:
  - x86 Assembly: [Iczelion's tutorial](https://github.com/VishalRashmika/Iczelions-Assembly-Tutorials/blob/main/README.md), [Win32 Assembler for Crackers by Goppit](https://www.scribd.com/document/659839309/Win32-Assembler-Coding-for-Crackers-PL-Kody-zrodlowe)
  - C/C++: [The C Programming language - by Kernighan & Ritchie](https://www.amazon.com/Programming-Language-2nd-Brian-Kernighan/dp/0131103628), [The C++ Programming language](https://www.amazon.com/C-Programming-Language-4th/dp/0321563840), [Linux Programming by example - by Kurt Wall](https://www.amazon.com/Linux-System-Programming-Embedded-Developers/dp/1593272200)
- [Windows System Programming](https://www.amazon.com/Windows-System-Programming-4th-Addison-Wesley/dp/0321657748) book

## Malware Unpacking
### 0x08 Manual Unpacking Techniques
- some ways...
  - way one : https://medium.com/@dbragetti/unpacking-malware-685de7093e5
  - way two : https://www.travismathison.com/posts/Manually-unpacking-malware/
- [manual unpacking](https://www.youtube.com/playlist?list=PLt9cUwGw6CYGfoSL9PUlpKi23z0_R2gz-)

## Advanced Techniques
### 0x09 Virtualization-based Protectors
- [Workshop: VM-based Obfuscation Analysis](https://synthesis.to/2021/10/21/vm_based_obfuscation.html)
- [Discussion on reverse engineering virtualization](https://www.youtube.com/watch?v=PAG3M7mWT2c&t=13229s)
- [VMProtect 2 – Detailed Analysis of the Virtual Machine Architecture](https://www.tetraph.com/security/vulnerability-scanning/vmprotect-2-detailed-analysis-virtual-machine-architecture/)
- [VMProtect 2 – Part Two, Complete Static Analysis](https://www.tetraph.com/security/vulnerability-scanning/vmprotect-2-part-two-complete-static-analysis/)
- [SpeakEasy: a writeup solving a challenge from UIUCTF 2021](https://medium.com/@acheron2302/speakeasy-writeup-3af3375ab63)
- [Tickling VMProtect with LLVM](https://www.synthesis.to/2021/10/21/vm_based_obfuscation.html)
- [Cracking programs with custom virtualization-based protectors](https://www.malwaretech.com/challenges/windows-reversing/vm1)

### 0x0a Malware Injection and Hooking
- [A walk-through various techniques (by Endgame)](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
- [Ready-made demos of various code injection techniques (source code)](https://github.com/odzhan/injection)
- [Review of various injection techniques (BlackHat 2019) Video - PDF](https://www.blackhat.com/us-19/briefings/schedule/index.html#practical-approach-to-process-injection-14279)
- [Author's PE injection demos (source code)](https://github.com/hasherezade/demos)
- ["Inline Hooking for programmers" (by MalwareTech) - Part 1 and Part 2](https://malwaretech.com/how-to-write-a-rootkit)
- [Windows API Hooking (article in Red Teaming Experiments)](https://redteaming.io/)
- [Simple userland rootkit - a case study](https://blog.malwarebytes.com/threat-analysis/2016/12/simple-userland-rootkit-a-case-study/)

### 0x0b Kernel-mode Malware
- [Starting with Windows Kernel Exploitation - setting up the lab](https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/)
- [Windows Kernel Programming](https://www.amazon.com/Windows-Internals-Part-Developer-Reference/dp/0735684189) book
- [Brief introduction to driver analysis methods by Matt Hand](https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/)
- [Additional guidance on driver reversing from VoidSec](https://voidsec.com/windows-driver-reversing-part-1/)
- [Rootkit analysis tutorial](http://www.sekoia.fr/blog/wp-content/uploads/2016/10/Rootkit-analysis-Use-case-on-HIDEDRV-v1.6.pdf)
- Kernel-mode rootkit techniques:
  - [Hooking IDT](https://resources.infosecinstitute.com/hooking-idt/)
  - [SSDT hooks](https://www.adlice.com/kernelmode-rootkits-part-1-ssdt-hooks/)
  - [IRP hooks](https://www.adlice.com/kernelmode-rootkits-part-2-irp-hooks/)
  - [Kernel filters](https://www.adlice.com/kernelmode-rootkits-part-3-kernel-filters/)

### 0x0c Going Deeper
- [Malware infecting MBR, bootkits, and UEFI firmware](https://securelist.com/bootkits-the-ultimate-in-persistent-malware/58221/)

## Learning Resources
### 0x0d Courses and Tutorials
- [Reversing: Secrets of Reverse Engineering Paperback – Illustrated, 1 April 2005](https://www.amazon.com.au/Reversing-Secrets-Engineering-Eldad-Eilam/dp/0764574817)
- [Practical Reverse Engineering: x86, x64, ARM, Windows Kernel, Reversing Tools, and Obfuscation 1st Edition](https://www.amazon.com/Practical-Reverse-Engineering-Reversing-Obfuscation/dp/1118787315)
- [Mytechnotalent's Reverse Engineering Repository](https://github.com/mytechnotalent/Reverse-Engineering)
- [Octopus Labs](http://legend.octopuslabs.io/sample-page.html)
- [Open Security Training](http://opensecuritytraining.info/Training.html)
- [Practical Malware Analysis learning materials](https://samsclass.info/126/126_S17.shtml)
- [Malware Analysis course (University of Cincinnati)](https://www.uc.edu/ce/cyber/courses/malware-analysis.html)
- [Red/purple teaming: a malware development course by 0xPat](https://twitter.com/0xPat)
- [Building C2 implants in C++](https://malwareunicorn.org/workshops.html)
- [Hasherezade's malware training repository](https://github.com/hasherezade/malware_training_vol1)

### 0x0e YouTube Channels and Videos
- [Malware Analysis For Hedgehogs](https://www.youtube.com/channel/UCVFXrUwuWZ3Uk6ZuIzP5RvQ)
- [OALabs](https://www.youtube.com/c/OALabs/videos)
- [Colin's channel about malware](https://www.youtube.com/channel/UCQN2DsjnYH60SFBIA6IkNwg)
- [DuMp-GuY TrIcKsTeR](https://www.youtube.com/user/hexacorn)

### 0x0f Recommended Books
- [Practical Malware Analysis: A Hands-On Guide to Dissecting Malicious Software](https://www.amazon.com/Practical-Malware-Analysis-Hands-On-Dissecting/dp/1593272901)
- [The Art of Computer Virus Research and Defense – Peter Szor](https://www.amazon.com/Art-Computer-Virus-Research-Defense/dp/0321304543)
- ["The "Ultimate"Anti-Debugging Reference" – by Peter Ferrie](https://www.amazon.com/Ultimate-Anti-Debugging-Reference-Peter-Ferrie/dp/1500494501)
- [Malware Analyst's Cookbook and DVD: Tools and Techniques for Fighting Malicious Code](https://www.amazon.com/Malware-Analysts-Cookbook-DVD-Techniques/dp/0470613033)
- [Hacker Disassembling Uncovered – by Kris Kaspersky](https://www.amazon.com/Hacker-Disassembling-Uncovered-Kaspersky/dp/193176946X)
- [The Rootkit Arsenal: Escape and Evasion in the Dark Corners of the System](https://www.amazon.com/Rootkit-Arsenal-Escape-Evasion-Corners/dp/144962636X)
- [Rootkits and Bootkits – by Alex Matrosov, Eugene Rodionov, and Sergey Bratus](https://www.amazon.com/Rootkits-Bootkits-Alex-Matrosov/dp/1593277164)
- [Windows System Programming (4th edition) – by Johnson M. Hart](https://www.amazon.com/Windows-System-Programming-4th-Addison-Wesley/dp/0321657748)
- [Gray Hat Python](https://www.amazon.com/Gray-Hat-Python-Programming-Engineers/dp/1593271921)

## Tips and Advice
### 0x10 Staying Motivated and Advancing Your Career
- Stay curious and eager to learn
- Practice, practice, practice
- Engage with the community
- Contribute and share your knowledge
- Stay up-to-date with the latest trends and techniques
- Develop strong programming skills in languages like C/C++, Python, and Assembly
- Embrace failure as a learning opportunity
- Maintain a safe and controlled environment for your analysis
- Respect intellectual property and adhere to ethical guidelines

### 0x11 Getting a Malware Analyst Job
- Contribute to the community through research, blog posts, or open source projects
- Stay active and engaged in the field by attending conferences and participating in CTFs
- Build a solid online presence by sharing your work and insights on platforms like GitHub and Twitter
- Network with industry professionals and join relevant communities and forums
- Continuously update your skills and knowledge through self-study and formal training programs

## Conclusion
This comprehensive roadmap provides a step-by-step guide for mastering reverse engineering and malware analysis. By following the suggested resources and engaging in practical exercises, you can build a strong foundation, develop advanced skills, and position yourself for a successful career in this field. Remember to stay motivated, curious, and always eager to learn. Good luck on your reverse engineering and malware analysis journey!

## Additional Resources
### Blogs and Websites
- [MalwareTech](https://www.malwaretech.com/)
- [Hasherezade's Blog](https://hshrzd.wordpress.com/)
- [Malwarebytes Labs](https://blog.malwarebytes.com/)
- [FireEye Threat Research Blog](https://www.fireeye.com/blog/threat-research.html)
- [Talos Intelligence Blog](https://blog.talosintelligence.com/)
- [Securelist by Kaspersky](https://securelist.com/)
- [The Malware Analyst's Cookbook](https://www.malwarecookbook.com/)
- [0xec](https://0xec.blogspot.com/)
- [Malwarebytes Unpacked](https://blog.malwarebytes.com/category/unpacked/)
- [SANS Internet Storm Center](https://isc.sans.edu/)
- [MalwareMustDie](http://malwaremustdie.blogspot.com/)
- [ReversingLabs](https://www.reversinglabs.com/blog)

### Forums and Communities
- [MalwareTips](https://malwaretips.com/)
- [Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/)
- [KernelMode.info](https://www.kernelmode.info/forum/)
- [Wilders Security Forums](https://www.wilderssecurity.com/)
- [Malware Analysis Forums on Reddit](https://www.reddit.com/r/Malware/)
- [VirusTotal Community](https://www.virustotal.com/gui/community)

### Tools and Software
- [IDA Pro](https://www.hex-rays.com/products/ida/)
- [Ghidra](https://ghidra-sre.org/)
- [x64dbg](https://x64dbg.com/)
- [OllyDbg](http://www.ollydbg.de/)
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/)
- [Wireshark](https://www.wireshark.org/)
- [Cuckoo Sandbox](https://cuckoosandbox.org/)
- [PEStudio](https://www.winitor.com/)
- [Volatility](https://www.volatilityfoundation.org/)
- [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/)
- [YARA](https://virustotal.github.io/yara/)
- [Capstone](https://www.capstone-engine.org/)
- [Radare2](https://www.radare.org/)
- [Binary Ninja](https://binary.ninja/)
- [Metasploit Framework](https://www.metasploit.com/)

### Online Platforms and Challenges
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [VirusTotal](https://www.virustotal.com/gui/home)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [Flare-On Challenge](https://www.fireeye.com/blog/threat-research/2019/08/announcing-the-sixth-annual-flare-on-challenge.html)
- [CTFTime](https://ctftime.org/)
- [Hack The Box](https://www.hackthebox.eu/)

## Acknowledgments
A big thank you to all the researchers, authors, and contributors who have shared their knowledge and resources in the field of reverse engineering and malware analysis. This roadmap wouldn't have been possible without their valuable contributions.

## Contributing
Contributions are welcome! If you have any suggestions, resources, or improvements to this roadmap, please feel free to open an issue or submit a pull request.


## channel 
## Join OrcaCyberWeapons on Telegram!

Are you ready to dive into the depths of cybersecurity, reverse engineering, and advanced threat analysis? Look no further than OrcaCyberWeapons, your gateway to the world of cutting-edge security research and exploration.

**What We Offer:**
- **Advanced Cybersecurity Insights:** Delve into the latest trends, techniques, and strategies employed by cyber adversaries, shedding light on the vast world of malware, exploits, APTs, and cybercrime across all platforms.
- **Reverse Engineering Expertise:** Uncover the inner workings of sophisticated malware, dissect exploit techniques, and explore the art of reverse engineering with our community of seasoned professionals and enthusiasts.
- **Malware Development and Analysis:** Gain valuable insights into the creation, analysis, and mitigation of malware, understanding its behavior, impact, and countermeasures.
- **APT Techniques and Defense Strategies:** Explore the realm of advanced persistent threats (APTs), dissect their tactics, and fortify your defenses against sophisticated cyber adversaries.

Whether you're a seasoned cybersecurity professional, an aspiring ethical hacker, or a curious enthusiast, OrcaCyberWeapons provides a platform for in-depth discussions, practical insights, and collaborative exploration of the ever-evolving cybersecurity landscape.

Join us on Telegram and embark on a journey of discovery, knowledge sharing, and continuous learning in the realm of cybersecurity and beyond.

[Join OrcaCyberWeapons on Telegram](https://t.me/OrcaCyberWeapons)
