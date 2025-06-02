(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PRESCRIPTION (err u101))
(define-constant ERR-ALREADY-FILLED (err u102))
(define-constant ERR-EXPIRED (err u103))
(define-constant ERR-INVALID-PHARMACY (err u104))
(define-constant ERR-INVALID-DOCTOR (err u105))

(define-data-var contract-owner principal tx-sender)

(define-map authorized-doctors principal bool)
(define-map authorized-pharmacies principal bool)

(define-map prescriptions 
    { prescription-id: uint }
    {
        patient-id: (string-utf8 64),
        doctor: principal,
        medication: (string-utf8 64),
        dosage: (string-utf8 32),
        quantity: uint,
        expiry: uint,
        filled: bool,
        filling-pharmacy: (optional principal),
        timestamp: uint
    }
)

(define-public (set-contract-owner (new-owner principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (var-set contract-owner new-owner))))

(define-public (add-authorized-doctor (doctor principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set authorized-doctors doctor true))))

(define-public (remove-authorized-doctor (doctor principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-delete authorized-doctors doctor))))

(define-public (add-authorized-pharmacy (pharmacy principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set authorized-pharmacies pharmacy true))))

(define-public (remove-authorized-pharmacy (pharmacy principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-delete authorized-pharmacies pharmacy))))

(define-read-only (is-authorized-doctor (doctor principal))
    (default-to false (map-get? authorized-doctors doctor)))

(define-read-only (is-authorized-pharmacy (pharmacy principal))
    (default-to false (map-get? authorized-pharmacies pharmacy)))

(define-public (create-prescription 
    (prescription-id uint)
    (patient-id (string-utf8 64))
    (medication (string-utf8 64))
    (dosage (string-utf8 32))
    (quantity uint)
    (expiry uint))
    (let
        ((doctor tx-sender))
        (begin
            (asserts! (is-authorized-doctor doctor) ERR-INVALID-DOCTOR)
            (asserts! (is-none (map-get? prescriptions {prescription-id: prescription-id})) ERR-INVALID-PRESCRIPTION)
            (ok (map-set prescriptions
                {prescription-id: prescription-id}
                {
                    patient-id: patient-id,
                    doctor: doctor,
                    medication: medication,
                    dosage: dosage,
                    quantity: quantity,
                    expiry: expiry,
                    filled: false,
                    filling-pharmacy: none,
                    timestamp: stacks-block-height
                })))))

(define-public (fill-prescription (prescription-id uint))
    (let
        ((pharmacy tx-sender)
         (prescription (unwrap! (map-get? prescriptions {prescription-id: prescription-id}) ERR-INVALID-PRESCRIPTION)))
        (begin
            (asserts! (is-authorized-pharmacy pharmacy) ERR-INVALID-PHARMACY)
            (asserts! (not (get filled prescription)) ERR-ALREADY-FILLED)
            (asserts! (< stacks-block-height (get expiry prescription)) ERR-EXPIRED)
            (ok (map-set prescriptions
                {prescription-id: prescription-id}
                (merge prescription
                    {
                        filled: true,
                        filling-pharmacy: (some pharmacy)
                    }))))))

(define-read-only (get-prescription (prescription-id uint))
    (map-get? prescriptions {prescription-id: prescription-id}))

(define-read-only (verify-prescription (prescription-id uint))
    (match (map-get? prescriptions {prescription-id: prescription-id})
        prescription (ok {
            is-valid: true,
            is-filled: (get filled prescription),
            is-expired: (> stacks-block-height (get expiry prescription))
        })
        ERR-INVALID-PRESCRIPTION))