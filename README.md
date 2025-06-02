# RxGuard

# 💊 RxGuard: Blockchain Prescription Verification Protocol

## 🎯 Overview
RxGuard is a secure and transparent prescription management system built on Stacks blockchain. It prevents prescription fraud, duplication, and unauthorized fills while maintaining a verifiable record of all prescriptions.

## ✨ Features
- 🏥 Doctor authorization system
- 💊 Pharmacy verification
- 📝 Secure prescription creation
- ✅ Prescription verification
- 🔒 Anti-fraud mechanisms
- ⏰ Expiration tracking

## 🚀 Usage

### For Contract Owners
```clarity
;; Add authorized doctors
(contract-call? .rxguard add-authorized-doctor 'DOCTOR_ADDRESS)

;; Add authorized pharmacies
(contract-call? .rxguard add-authorized-pharmacy 'PHARMACY_ADDRESS)
```

### For Doctors
```clarity
;; Create new prescription
(contract-call? .rxguard create-prescription 
    u1234                  ;; prescription-id
    "PATIENT_ID"          ;; patient-id
    "Medication Name"     ;; medication
    "1 pill twice daily"  ;; dosage
    u30                   ;; quantity
    u720                  ;; expiry blocks
)
```

### For Pharmacies
```clarity
;; Fill prescription
(contract-call? .rxguard fill-prescription u1234)

;; Verify prescription
(contract-call? .rxguard verify-prescription u1234)
```

## 🔧 Installation
1. Clone the repository
2. Install Clarinet
3. Run `clarinet test`
4. Deploy using `clarinet deploy`

## 🔐 Security
- Only authorized doctors can create prescriptions
- Only authorized pharmacies can fill prescriptions
- Prescriptions cannot be filled multiple times
- Expired prescriptions cannot be filled

## 📝 License
MIT License
```


