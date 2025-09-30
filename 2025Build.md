# My Ultimate Build 2025 — Full Technical Write-Up

---

## AMD Ryzen Threadripper 7980X  
**Technical Details:**  
- **Architecture:** Zen 4, 5 nm process  
- **Cores / Threads:** 64 cores, 128 threads  
- **Base / Boost Frequency:** 3.2 GHz base, up to 5.1 GHz boost  
- **Cache:** 64 MB L2 + 256 MB L3  
- **TDP:** 350 W  
- **Memory Support:** Quad-channel DDR5, ECC Registered DIMM, up to 1 TB  
- **PCIe Support:** 80 usable PCIe 5.0 lanes  
- **Why It’s Awesome:**  
  The 7980X is one of the most powerful workstation CPUs available, combining extreme core density with very high single-thread boosts. This makes it equally capable of handling AI inference, Plex/Emby transcoding, Docker workloads, large virtual machine farms, and CPU-bound simulations. Its quad-channel ECC DDR5 memory support ensures stability for enterprise workloads while PCIe 5.0 lanes future-proof the system for multiple GPUs, NVMe arrays, and HBAs.  

🔗 [AMD Ryzen Threadripper 7980X – Official Page](https://www.amd.com/en/partner/articles/unchained-creativity-threadripper-7000-series.html)

---

## ASUS Pro WS TRX50-SAGE WIFI  
**Technical Details:**  
- **Socket / Chipset:** sTR5, TRX50  
- **Form Factor:** Extended ATX (12” × 11”) workstation board  
- **Memory Support:** 4× DDR5 ECC R-DIMM slots, up to 1 TB quad-channel  
- **Power Delivery:** 36-stage VRM design with active heatsinks and ProCool II connectors  
- **Expansion Slots:** Four PCIe 5.0 ×16 slots for GPUs, HBAs, or accelerators  
- **Storage Connectivity:**  
  - 2× PCIe 5.0 M.2 slots  
  - 1× PCIe 4.0 M.2 slot  
  - SlimSAS connectors for high-density NVMe expansion  
- **Networking:** Onboard dual LAN (10 GbE + 2.5 GbE) and Wi-Fi 6E  
- **Management:** IPMI remote management via optional ASUS BMC module  
- **Why It’s Awesome:**  
  Designed specifically for high-end workstation and server builds, this motherboard ensures long-term stability under continuous workloads. The VRM design delivers clean power to even the most power-hungry CPUs like the 7980X. With multiple PCIe 5.0 slots and SlimSAS connectors, it is built for extreme expandability.  

🔗 [ASUS Pro WS TRX50-SAGE WIFI – Official Page](https://www.asus.com/us/motherboards-components/motherboards/workstation/pro-ws-trx50-sage-wifi/)

---

## G.SKILL Zeta R5 NEO 128 GB (4×32 GB) DDR5-6400 ECC RDIMM  
**Technical Details:**  
- **Type:** DDR5 Registered ECC DIMM  
- **Capacity:** 128 GB (4×32 GB)  
- **Speed / Latency:** DDR5-6400, CL32-39-39-102  
- **Voltage:** 1.40 V  
- **Why It’s Awesome:**  
  ECC R-DIMMs are the gold standard for reliability. This kit combines ECC integrity with enthusiast-grade performance (DDR5-6400 at CL32). It is validated for AMD Threadripper 7000 and TRX50 platforms, making it a rare blend of raw speed and server-class dependability.  

🔗 [G.SKILL Zeta R5 NEO – Official Page](https://www.gskill.com/product/400/409/1697525750/F5-6000R3036G32GQ4-ZR5NK-EOL)

---

## Samsung 990 PRO 2 TB NVMe SSD (×2)  
**Technical Details:**  
- **Interface:** PCIe 4.0 ×4 NVMe 2.0  
- **Read / Write Performance:** Up to 7,450 MB/s read, 6,900 MB/s write  
- **Random IOPS:** Up to 1.55M read, 1.4M write  
- **NAND:** Samsung V-NAND 7th Gen  
- **Controller:** Samsung in-house controller  
- **Endurance:** 1,200 TBW (2 TB model)  
- **Why It’s Awesome:**  
  These drives are among the fastest PCIe Gen4 SSDs on the market. They are ideal for Unraid cache pools, handling metadata and high-IOPS tasks like Docker, VMs, and fast file writes. Samsung’s in-house controller and firmware reliability make them an industry benchmark.  

🔗 [Samsung 990 PRO – Official Page](https://semiconductor.samsung.com/consumer-storage/internal-ssd/990-pro/)

---

## NVIDIA RTX A4000 (PNY)  
**Technical Details:**  
- **Architecture:** NVIDIA Ampere  
- **CUDA Cores:** 6,144  
- **Memory:** 16 GB GDDR6 ECC  
- **Memory Bandwidth:** 448 GB/s  
- **TDP:** 140 W  
- **Display Outputs:** 4× DisplayPort 1.4a  
- **Why It’s Awesome:**  
  The RTX A4000 is a workstation GPU that balances compute power and efficiency. With ECC VRAM, CUDA/RT/Tensor cores, and NVENC/NVDEC hardware encoders, it excels at GPU passthrough, Plex/Emby transcoding, AI inference, and professional workloads without the massive power draw of flagship GPUs.  

🔗 [PNY NVIDIA RTX A4000 – Official Page](https://www.pny.com/nvidia-rtx-a4000)

---

## Broadcom / LSI 9305-16i Host Bus Adapter  
**Technical Details:**  
- **Interface:** PCIe 3.0 ×8  
- **Ports:** 16 internal SAS/SATA 12 Gb/s lanes (4× SFF-8643 connectors)  
- **Mode:** IT (initiator target) firmware mode for direct passthrough  
- **Bandwidth:** 9.6 GB/s total  
- **Why It’s Awesome:**  
  Unlike RAID controllers, this HBA runs in IT mode to expose each drive directly to Unraid. That ensures parity and disk management are handled in software, giving maximum flexibility. It is a proven, enterprise-class solution widely used in data centers for high-density storage builds.  

🔗 [Broadcom 9305-16i – Product Page](https://www.serversupply.com/CONTROLLERS/SAS-SATA/HOST%20BUS%20ADAPTER/BROADCOM/9305-16I_274680.htm)

---

## Corsair RM1200x Shift (1200 W, ATX 3.0/3.1)  
**Technical Details:**  
- **Certification:** 80 PLUS Gold, Cybenetics Gold efficiency  
- **Form Factor:** ATX 3.0, PCIe 5.0 compliant  
- **Cabling:** Fully modular, side-interface connector system  
- **Cooling:** 140 mm fan with Zero RPM mode  
- **Warranty:** 10 years  
- **Why It’s Awesome:**  
  The Shift design makes cable routing significantly cleaner by orienting connectors to the side. Combined with 1200 W of ATX 3.0 power headroom, it easily handles transient GPU spikes and multiple accelerators. Corsair’s long warranty and proven reliability make it a trusted PSU for demanding builds.  

🔗 [Corsair RM1200x Shift – Official Page](https://www.corsair.com/us/en/p/psu/cp-9020254-na/rm1200x-shift-80-plus-gold-fully-modular-atx-power-supply-cp-9020254-na)

---

## Fractal Design Define 7 XL  
**Technical Details:**  
- **Form Factor:** Full-tower case  
- **Drive Capacity:** Up to 18× 3.5” HDDs in storage layout  
- **Cooling Support:** Up to 9 fans, radiator support up to 480 mm  
- **Noise Control:** Sound-dampened panels and clean airflow path  
- **Motherboard Support:** Up to EEB and CEB workstation boards  
- **Why It’s Awesome:**  
  One of the most versatile full-tower cases available, the Define 7 XL balances quiet operation, storage capacity, and extreme expandability. Its modular drive cages make it ideal for large Unraid builds.  

🔗 [Fractal Define 7 XL – Official Page](https://www.fractal-design.com/products/cases/define/define-7-xl/black/)

---

## Noctua NH-U14S TR4-SP3  
**Technical Details:**  
- **Compatibility:** Specifically engineered for AMD Threadripper TR4/SP3 sockets  
- **Cooling:** 6 copper heatpipes, offset base for full IHS coverage  
- **Fan:** 140 mm NF-A15 PWM  
- **Height:** 165 mm (fits Define 7 XL easily)  
- **Why It’s Awesome:**  
  This cooler is tuned for the massive IHS of Threadripper CPUs. It provides high thermal headroom with very low noise, leveraging Noctua’s premium fans and long-term reliability.  

🔗 [Noctua NH-U14S TR4-SP3 – Official Page](https://noctua.at/en/nh-u14s-tr4-sp3)

---

# Other Accessories

## Be Quiet! Silent Wings 4 (140 mm PWM, ×3)  
- Advanced fan blade design with high static pressure  
- Fluid-dynamic bearings for long life  
- Whisper-quiet operation with excellent thermal efficiency  
- Perfect for top exhaust configuration  

🔗 [Silent Wings 4 – Official Page](https://www.bequiet.com/en/casefans/silent-wings-4/3696)

---

## Cable Matters SFF-8643 to SATA Forward Breakouts (×4)  
- Converts each SFF-8643 port into 4 SATA connectors  
- Required for connecting 14 drives to the Broadcom HBA  
- Durable cabling with clean sleeving for airflow and reliability  

---

## Fractal Design Type-B HDD Tray Kits (×3 kits)  
- Adds 6 additional trays to support all 14 HDDs  
- Tool-less mounting and perfect fit in Define 7 XL  

🔗 [Fractal Type-B Tray Kit – Official Page](https://www.fractal-design.com/products/accessories/mounting/hdd-kit-type-b-2-pack/black/)

---
