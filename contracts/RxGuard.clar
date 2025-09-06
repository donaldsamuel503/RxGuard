(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PRESCRIPTION (err u101))
(define-constant ERR-ALREADY-FILLED (err u102))
(define-constant ERR-EXPIRED (err u103))
(define-constant ERR-INVALID-PHARMACY (err u104))
(define-constant ERR-INVALID-DOCTOR (err u105))
(define-constant ERR-INVALID-AUDIT-ACCESS (err u106))
(define-constant ERR-INVALID-AUDIT-ID (err u107))
(define-constant ERR-INVALID-TRANSFER (err u108))
(define-constant ERR-TRANSFER-NOT-PENDING (err u109))
(define-constant ERR-TRANSFER-ALREADY-EXISTS (err u110))
(define-constant ERR-SAME-PHARMACY (err u111))
(define-constant ERR-PRESCRIPTION-FILLED (err u112))
(define-constant ERR-NO-REFILLS-REMAINING (err u113))
(define-constant ERR-REFILL-TOO-EARLY (err u114))
(define-constant ERR-INVALID-REFILL-CONFIG (err u115))
(define-constant ERR-REFILL-NOT-FOUND (err u116))
(define-constant ERR-REFILL-ALREADY-PROCESSED (err u117))
(define-constant ERR-NOT-EMERGENCY-RESPONDER (err u118))
(define-constant ERR-INVALID-EMERGENCY-OVERRIDE (err u119))
(define-constant ERR-OVERRIDE-EXPIRED (err u120))
(define-constant ERR-OVERRIDE-ALREADY-EXISTS (err u121))
(define-constant ERR-INSUFFICIENT-JUSTIFICATION (err u122))

(define-data-var contract-owner principal tx-sender)
(define-data-var audit-counter uint u0)
(define-data-var transfer-counter uint u0)
(define-data-var refill-counter uint u0)
(define-data-var emergency-override-counter uint u0)

(define-map authorized-doctors
    principal
    bool
)
(define-map authorized-pharmacies
    principal
    bool
)

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
        timestamp: uint,
    }
)

(define-map audit-events
    { audit-id: uint }
    {
        prescription-id: uint,
        event-type: (string-ascii 32),
        actor: principal,
        timestamp: uint,
        block-height: uint,
        details: (string-utf8 256),
    }
)

(define-map prescription-audit-trail
    { prescription-id: uint }
    {
        creation-audit-id: uint,
        fill-audit-id: (optional uint),
        verification-count: uint,
        last-verification-audit-id: (optional uint),
        compliance-status: (string-ascii 16),
    }
)

(define-map audit-statistics
    { period: (string-ascii 16) }
    {
        total-events: uint,
        prescription-creations: uint,
        prescription-fills: uint,
        verification-requests: uint,
        compliance-violations: uint,
    }
)

(define-map prescription-transfers
    { transfer-id: uint }
    {
        prescription-id: uint,
        source-pharmacy: principal,
        destination-pharmacy: principal,
        requester: principal,
        transfer-fee: uint,
        request-timestamp: uint,
        source-approval: bool,
        destination-approval: bool,
        transfer-status: (string-ascii 16),
        completion-timestamp: (optional uint),
        transfer-reason: (string-utf8 128),
    }
)

(define-map prescription-transfer-lookup
    { prescription-id: uint }
    {
        active-transfer-id: (optional uint),
        transfer-count: uint,
    }
)

(define-map prescription-refill-config
    { prescription-id: uint }
    {
        max-refills: uint,
        refills-used: uint,
        days-between-refills: uint,
        early-refill-threshold: uint,
        last-refill-timestamp: (optional uint),
        next-eligible-refill: (optional uint),
        requires-doctor-approval: bool,
    }
)

(define-map refill-requests
    { refill-id: uint }
    {
        prescription-id: uint,
        requesting-pharmacy: principal,
        request-timestamp: uint,
        is-early-refill: bool,
        early-refill-reason: (optional (string-utf8 128)),
        doctor-approval: bool,
        pharmacy-approval: bool,
        refill-status: (string-ascii 16),
        processed-timestamp: (optional uint),
        dispensed-quantity: (optional uint),
    }
)

(define-map refill-history
    { prescription-id: uint, refill-sequence: uint }
    {
        refill-id: uint,
        dispensing-pharmacy: principal,
        dispense-timestamp: uint,
        quantity-dispensed: uint,
        days-early: uint,
        approval-required: bool,
        insurance-claim: (optional (string-utf8 64)),
    }
)

(define-public (set-contract-owner (new-owner principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (var-set contract-owner new-owner))
    )
)

(define-public (add-authorized-doctor (doctor principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set authorized-doctors doctor true))
    )
)

(define-public (remove-authorized-doctor (doctor principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-delete authorized-doctors doctor))
    )
)

(define-public (add-authorized-pharmacy (pharmacy principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-set authorized-pharmacies pharmacy true))
    )
)

(define-public (remove-authorized-pharmacy (pharmacy principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (ok (map-delete authorized-pharmacies pharmacy))
    )
)

(define-read-only (is-authorized-doctor (doctor principal))
    (default-to false (map-get? authorized-doctors doctor))
)

(define-read-only (is-authorized-pharmacy (pharmacy principal))
    (default-to false (map-get? authorized-pharmacies pharmacy))
)

(define-private (log-audit-event
        (prescription-id uint)
        (event-type (string-ascii 32))
        (details (string-utf8 256))
    )
    (let (
            (current-counter (var-get audit-counter))
            (new-audit-id (+ current-counter u1))
        )
        (begin
            (var-set audit-counter new-audit-id)
            (map-set audit-events { audit-id: new-audit-id } {
                prescription-id: prescription-id,
                event-type: event-type,
                actor: tx-sender,
                timestamp: stacks-block-height,
                block-height: stacks-block-height,
                details: details,
            })
            (update-audit-statistics event-type)
            new-audit-id
        )
    )
)

(define-private (update-audit-statistics (event-type (string-ascii 32)))
    (let (
            (current-period "current")
            (stats (default-to {
                total-events: u0,
                prescription-creations: u0,
                prescription-fills: u0,
                verification-requests: u0,
                compliance-violations: u0,
            }
                (map-get? audit-statistics { period: current-period })
            ))
        )
        (map-set audit-statistics { period: current-period } {
            total-events: (+ (get total-events stats) u1),
            prescription-creations: (if (is-eq event-type "PRESCRIPTION_CREATED")
                (+ (get prescription-creations stats) u1)
                (get prescription-creations stats)
            ),
            prescription-fills: (if (is-eq event-type "PRESCRIPTION_FILLED")
                (+ (get prescription-fills stats) u1)
                (get prescription-fills stats)
            ),
            verification-requests: (if (is-eq event-type "PRESCRIPTION_VERIFIED")
                (+ (get verification-requests stats) u1)
                (get verification-requests stats)
            ),
            compliance-violations: (if (is-eq event-type "COMPLIANCE_VIOLATION")
                (+ (get compliance-violations stats) u1)
                (get compliance-violations stats)
            ),
        })
    )
)

(define-private (initialize-audit-trail
        (prescription-id uint)
        (creation-audit-id uint)
    )
    (map-set prescription-audit-trail { prescription-id: prescription-id } {
        creation-audit-id: creation-audit-id,
        fill-audit-id: none,
        verification-count: u0,
        last-verification-audit-id: none,
        compliance-status: "COMPLIANT",
    })
)

(define-private (update-audit-trail-fill
        (prescription-id uint)
        (fill-audit-id uint)
    )
    (let ((current-trail (unwrap-panic (map-get? prescription-audit-trail { prescription-id: prescription-id }))))
        (map-set prescription-audit-trail { prescription-id: prescription-id }
            (merge current-trail { fill-audit-id: (some fill-audit-id) })
        )
    )
)

(define-private (update-audit-trail-verification
        (prescription-id uint)
        (verification-audit-id uint)
    )
    (let ((current-trail (unwrap-panic (map-get? prescription-audit-trail { prescription-id: prescription-id }))))
        (map-set prescription-audit-trail { prescription-id: prescription-id }
            (merge current-trail {
                verification-count: (+ (get verification-count current-trail) u1),
                last-verification-audit-id: (some verification-audit-id),
            })
        )
    )
)

(define-public (create-prescription
        (prescription-id uint)
        (patient-id (string-utf8 64))
        (medication (string-utf8 64))
        (dosage (string-utf8 32))
        (quantity uint)
        (expiry uint)
    )
    (let (
            (doctor tx-sender)
            (details (concat u"Patient: "
                (concat patient-id (concat u", Medication: " medication))
            ))
        )
        (begin
            (asserts! (is-authorized-doctor doctor) ERR-INVALID-DOCTOR)
            (asserts!
                (is-none (map-get? prescriptions { prescription-id: prescription-id }))
                ERR-INVALID-PRESCRIPTION
            )
            (let ((creation-audit-id (log-audit-event prescription-id "PRESCRIPTION_CREATED" details)))
                (begin
                    (map-set prescriptions { prescription-id: prescription-id } {
                        patient-id: patient-id,
                        doctor: doctor,
                        medication: medication,
                        dosage: dosage,
                        quantity: quantity,
                        expiry: expiry,
                        filled: false,
                        filling-pharmacy: none,
                        timestamp: stacks-block-height,
                    })
                    (initialize-audit-trail prescription-id creation-audit-id)
                    (ok true)
                )
            )
        )
    )
)

(define-read-only (get-prescription (prescription-id uint))
    (map-get? prescriptions { prescription-id: prescription-id })
)

(define-public (verify-prescription (prescription-id uint))
    (match (map-get? prescriptions { prescription-id: prescription-id })
        prescription (let (
                (verification-audit-id (log-audit-event prescription-id "PRESCRIPTION_VERIFIED"
                    u"Verification request"
                ))
                (is-expired-bool (> stacks-block-height (get expiry prescription)))
            )
            (begin
                (update-audit-trail-verification prescription-id
                    verification-audit-id
                )
                (ok {
                    is-valid: true,
                    is-filled: (get filled prescription),
                    is-expired: is-expired-bool,
                })
            )
        )
        ERR-INVALID-PRESCRIPTION
    )
)

(define-read-only (get-audit-event (audit-id uint))
    (map-get? audit-events { audit-id: audit-id })
)

(define-read-only (get-prescription-audit-trail (prescription-id uint))
    (map-get? prescription-audit-trail { prescription-id: prescription-id })
)

(define-read-only (get-audit-statistics (period (string-ascii 16)))
    (map-get? audit-statistics { period: period })
)

(define-public (generate-compliance-report (prescription-id uint))
    (let (
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: prescription-id })
                ERR-INVALID-PRESCRIPTION
            ))
            (audit-trail (unwrap!
                (map-get? prescription-audit-trail { prescription-id: prescription-id })
                ERR-INVALID-PRESCRIPTION
            ))
            (creation-event (unwrap!
                (map-get? audit-events { audit-id: (get creation-audit-id audit-trail) })
                ERR-INVALID-AUDIT-ID
            ))
        )
        (begin
            (asserts!
                (or
                    (is-eq tx-sender (var-get contract-owner))
                    (is-authorized-doctor tx-sender)
                    (is-authorized-pharmacy tx-sender)
                )
                ERR-INVALID-AUDIT-ACCESS
            )
            (let (
                    (details u"Compliance report generated")
                    (report-audit-id (log-audit-event prescription-id "COMPLIANCE_REPORT" details))
                )
                (ok {
                    prescription-id: prescription-id,
                    patient-id: (get patient-id prescription),
                    prescribing-doctor: (get doctor prescription),
                    creation-timestamp: (get timestamp creation-event),
                    fill-status: (get filled prescription),
                    filling-pharmacy: (get filling-pharmacy prescription),
                    verification-count: (get verification-count audit-trail),
                    compliance-status: (get compliance-status audit-trail),
                    report-timestamp: stacks-block-height,
                    report-audit-id: report-audit-id,
                })
            )
        )
    )
)

(define-public (audit-prescription-lifecycle (prescription-id uint))
    (let ((audit-trail (unwrap!
            (map-get? prescription-audit-trail { prescription-id: prescription-id })
            ERR-INVALID-PRESCRIPTION
        )))
        (begin
            (asserts!
                (or
                    (is-eq tx-sender (var-get contract-owner))
                    (is-authorized-doctor tx-sender)
                    (is-authorized-pharmacy tx-sender)
                )
                ERR-INVALID-AUDIT-ACCESS
            )
            (let (
                    (creation-event (unwrap!
                        (map-get? audit-events { audit-id: (get creation-audit-id audit-trail) })
                        ERR-INVALID-AUDIT-ID
                    ))
                    (fill-event (match (get fill-audit-id audit-trail)
                        some-id (map-get? audit-events { audit-id: some-id })
                        none
                    ))
                    (last-verification-event (match (get last-verification-audit-id audit-trail)
                        some-id (map-get? audit-events { audit-id: some-id })
                        none
                    ))
                )
                (ok {
                    prescription-id: prescription-id,
                    creation-event: creation-event,
                    fill-event: fill-event,
                    last-verification-event: last-verification-event,
                    total-verifications: (get verification-count audit-trail),
                    compliance-status: (get compliance-status audit-trail),
                })
            )
        )
    )
)

(define-public (flag-compliance-violation
        (prescription-id uint)
        (violation-details (string-utf8 256))
    )
    (let ((audit-trail (unwrap!
            (map-get? prescription-audit-trail { prescription-id: prescription-id })
            ERR-INVALID-PRESCRIPTION
        )))
        (begin
            (asserts!
                (or
                    (is-eq tx-sender (var-get contract-owner))
                    (is-authorized-doctor tx-sender)
                    (is-authorized-pharmacy tx-sender)
                )
                ERR-INVALID-AUDIT-ACCESS
            )
            (let ((violation-audit-id (log-audit-event prescription-id "COMPLIANCE_VIOLATION"
                    violation-details
                )))
                (begin
                    (map-set prescription-audit-trail { prescription-id: prescription-id }
                        (merge audit-trail { compliance-status: "VIOLATION" })
                    )
                    (ok violation-audit-id)
                )
            )
        )
    )
)

(define-read-only (get-system-audit-summary)
    (let ((current-stats (default-to {
            total-events: u0,
            prescription-creations: u0,
            prescription-fills: u0,
            verification-requests: u0,
            compliance-violations: u0,
        }
            (map-get? audit-statistics { period: "current" })
        )))
        (ok {
            total-audit-events: (get total-events current-stats),
            prescription-creations: (get prescription-creations current-stats),
            prescription-fills: (get prescription-fills current-stats),
            verification-requests: (get verification-requests current-stats),
            compliance-violations: (get compliance-violations current-stats),
            current-audit-counter: (var-get audit-counter),
        })
    )
)

(define-public (request-prescription-transfer
        (prescription-id uint)
        (destination-pharmacy principal)
        (transfer-reason (string-utf8 128))
        (transfer-fee uint)
    )
    (let (
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: prescription-id })
                ERR-INVALID-PRESCRIPTION
            ))
            (current-lookup (default-to
                { active-transfer-id: none, transfer-count: u0 }
                (map-get? prescription-transfer-lookup { prescription-id: prescription-id })
            ))
            (current-counter (var-get transfer-counter))
            (new-transfer-id (+ current-counter u1))
        )
        (begin
            (asserts! (not (get filled prescription)) ERR-PRESCRIPTION-FILLED)
            (asserts! (is-authorized-pharmacy destination-pharmacy) ERR-INVALID-PHARMACY)
            (asserts! (is-none (get active-transfer-id current-lookup)) ERR-TRANSFER-ALREADY-EXISTS)
            (var-set transfer-counter new-transfer-id)
            (map-set prescription-transfers { transfer-id: new-transfer-id } {
                prescription-id: prescription-id,
                source-pharmacy: (get doctor prescription),
                destination-pharmacy: destination-pharmacy,
                requester: tx-sender,
                transfer-fee: transfer-fee,
                request-timestamp: stacks-block-height,
                source-approval: false,
                destination-approval: false,
                transfer-status: "PENDING",
                completion-timestamp: none,
                transfer-reason: transfer-reason,
            })
            (map-set prescription-transfer-lookup { prescription-id: prescription-id } {
                active-transfer-id: (some new-transfer-id),
                transfer-count: (+ (get transfer-count current-lookup) u1),
            })
            (let ((audit-details (concat u"Transfer requested for new pharmacy, Reason: " transfer-reason)))
                (log-audit-event prescription-id "TRANSFER_REQUESTED" audit-details)
            )
            (ok new-transfer-id)
        )
    )
)

(define-public (approve-transfer-source (transfer-id uint))
    (let (
            (transfer (unwrap!
                (map-get? prescription-transfers { transfer-id: transfer-id })
                ERR-INVALID-TRANSFER
            ))
        )
        (begin
            (asserts!
                (is-eq tx-sender (get source-pharmacy transfer))
                ERR-NOT-AUTHORIZED
            )
            (asserts!
                (is-eq (get transfer-status transfer) "PENDING")
                ERR-TRANSFER-NOT-PENDING
            )
            (map-set prescription-transfers { transfer-id: transfer-id }
                (merge transfer { source-approval: true })
            )
            (let ((audit-details u"Source pharmacy approved transfer request"))
                (log-audit-event (get prescription-id transfer) "TRANSFER_SOURCE_APPROVED" audit-details)
            )
            (try! (check-and-complete-transfer transfer-id))
            (ok true)
        )
    )
)

(define-public (approve-transfer-destination (transfer-id uint))
    (let (
            (transfer (unwrap!
                (map-get? prescription-transfers { transfer-id: transfer-id })
                ERR-INVALID-TRANSFER
            ))
        )
        (begin
            (asserts!
                (is-eq tx-sender (get destination-pharmacy transfer))
                ERR-NOT-AUTHORIZED
            )
            (asserts!
                (is-eq (get transfer-status transfer) "PENDING")
                ERR-TRANSFER-NOT-PENDING
            )
            (map-set prescription-transfers { transfer-id: transfer-id }
                (merge transfer { destination-approval: true })
            )
            (let ((audit-details u"Destination pharmacy approved transfer request"))
                (log-audit-event (get prescription-id transfer) "TRANSFER_DEST_APPROVED" audit-details)
            )
            (try! (check-and-complete-transfer transfer-id))
            (ok true)
        )
    )
)

(define-private (check-and-complete-transfer (transfer-id uint))
    (let (
            (transfer (unwrap!
                (map-get? prescription-transfers { transfer-id: transfer-id })
                ERR-INVALID-TRANSFER
            ))
        )
        (if (and (get source-approval transfer) (get destination-approval transfer))
            (complete-prescription-transfer transfer-id)
            (ok false)
        )
    )
)

(define-private (complete-prescription-transfer (transfer-id uint))
    (let (
            (transfer (unwrap!
                (map-get? prescription-transfers { transfer-id: transfer-id })
                ERR-INVALID-TRANSFER
            ))
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: (get prescription-id transfer) })
                ERR-INVALID-PRESCRIPTION
            ))
        )
        (begin
            (map-set prescription-transfers { transfer-id: transfer-id }
                (merge transfer {
                    transfer-status: "COMPLETED",
                    completion-timestamp: (some stacks-block-height),
                })
            )
            (map-set prescriptions { prescription-id: (get prescription-id transfer) }
                (merge prescription {
                    filled: true,
                    filling-pharmacy: (some (get destination-pharmacy transfer)),
                })
            )
            (map-set prescription-transfer-lookup { prescription-id: (get prescription-id transfer) } {
                active-transfer-id: none,
                transfer-count: (get transfer-count (unwrap!
                    (map-get? prescription-transfer-lookup { prescription-id: (get prescription-id transfer) })
                    ERR-INVALID-PRESCRIPTION
                )),
            })
            (let ((audit-details u"Prescription transfer completed successfully"))
                (log-audit-event (get prescription-id transfer) "TRANSFER_COMPLETED" audit-details)
            )
            (ok true)
        )
    )
)

(define-public (reject-transfer (transfer-id uint))
    (let (
            (transfer (unwrap!
                (map-get? prescription-transfers { transfer-id: transfer-id })
                ERR-INVALID-TRANSFER
            ))
        )
        (begin
            (asserts!
                (or
                    (is-eq tx-sender (get source-pharmacy transfer))
                    (is-eq tx-sender (get destination-pharmacy transfer))
                    (is-eq tx-sender (var-get contract-owner))
                )
                ERR-NOT-AUTHORIZED
            )
            (asserts!
                (is-eq (get transfer-status transfer) "PENDING")
                ERR-TRANSFER-NOT-PENDING
            )
            (map-set prescription-transfers { transfer-id: transfer-id }
                (merge transfer { transfer-status: "REJECTED" })
            )
            (map-set prescription-transfer-lookup { prescription-id: (get prescription-id transfer) } {
                active-transfer-id: none,
                transfer-count: (get transfer-count (unwrap!
                    (map-get? prescription-transfer-lookup { prescription-id: (get prescription-id transfer) })
                    ERR-INVALID-PRESCRIPTION
                )),
            })
            (let ((audit-details u"Transfer request rejected"))
                (log-audit-event (get prescription-id transfer) "TRANSFER_REJECTED" audit-details)
            )
            (ok true)
        )
    )
)

(define-read-only (get-prescription-transfer (transfer-id uint))
    (map-get? prescription-transfers { transfer-id: transfer-id })
)

(define-read-only (get-prescription-transfer-status (prescription-id uint))
    (map-get? prescription-transfer-lookup { prescription-id: prescription-id })
)

(define-read-only (get-transfer-counter)
    (var-get transfer-counter)
)

;; Refill Management System
(define-public (configure-prescription-refills
        (prescription-id uint)
        (max-refills uint)
        (days-between-refills uint)
        (early-refill-threshold uint)
        (requires-doctor-approval bool)
    )
    (let (
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: prescription-id })
                ERR-INVALID-PRESCRIPTION
            ))
        )
        (begin
            (asserts!
                (is-eq tx-sender (get doctor prescription))
                ERR-NOT-AUTHORIZED
            )
            (map-set prescription-refill-config { prescription-id: prescription-id } {
                max-refills: max-refills,
                refills-used: u0,
                days-between-refills: days-between-refills,
                early-refill-threshold: early-refill-threshold,
                last-refill-timestamp: none,
                next-eligible-refill: none,
                requires-doctor-approval: requires-doctor-approval,
            })
            (let ((audit-details u"Refill configuration set for prescription"))
                (log-audit-event prescription-id "REFILL_CONFIG_SET" audit-details)
            )
            (ok true)
        )
    )
)

(define-public (request-refill
        (prescription-id uint)
        (requesting-pharmacy principal)
        (requested-quantity uint)
        (early-refill-reason (optional (string-utf8 128)))
    )
    (let (
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: prescription-id })
                ERR-INVALID-PRESCRIPTION
            ))
            (refill-config (unwrap!
                (map-get? prescription-refill-config { prescription-id: prescription-id })
                ERR-INVALID-REFILL-CONFIG
            ))
            (current-counter (var-get refill-counter))
            (new-refill-id (+ current-counter u1))
            (is-early (check-early-refill refill-config))
        )
        (begin
            (asserts! (is-authorized-pharmacy requesting-pharmacy) ERR-INVALID-PHARMACY)
            (asserts!
                (< (get refills-used refill-config) (get max-refills refill-config))
                ERR-NO-REFILLS-REMAINING
            )
            (if (and is-early (not (get requires-doctor-approval refill-config)))
                (asserts! false ERR-REFILL-TOO-EARLY)
                true
            )
            (var-set refill-counter new-refill-id)
            (map-set refill-requests { refill-id: new-refill-id } {
                prescription-id: prescription-id,
                requesting-pharmacy: requesting-pharmacy,
                request-timestamp: stacks-block-height,
                is-early-refill: is-early,
                early-refill-reason: early-refill-reason,
                doctor-approval: (not (get requires-doctor-approval refill-config)),
                pharmacy-approval: false,
                refill-status: "PENDING",
                processed-timestamp: none,
                dispensed-quantity: (some requested-quantity),
            })
            (let ((audit-details (if is-early
                    u"Early refill requested with medical justification"
                    u"Regular refill requested within normal timeframe"
                )))
                (log-audit-event prescription-id "REFILL_REQUESTED" audit-details)
            )
            (ok new-refill-id)
        )
    )
)

(define-private (check-early-refill (refill-config (tuple (max-refills uint) (refills-used uint) (days-between-refills uint) (early-refill-threshold uint) (last-refill-timestamp (optional uint)) (next-eligible-refill (optional uint)) (requires-doctor-approval bool))))
    (match (get last-refill-timestamp refill-config)
        last-refill
            (let ((days-since-last (- stacks-block-height last-refill)))
                (< days-since-last (- (get days-between-refills refill-config) (get early-refill-threshold refill-config)))
            )
        false
    )
)

(define-public (approve-refill-doctor (refill-id uint))
    (let (
            (refill-request (unwrap!
                (map-get? refill-requests { refill-id: refill-id })
                ERR-REFILL-NOT-FOUND
            ))
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: (get prescription-id refill-request) })
                ERR-INVALID-PRESCRIPTION
            ))
        )
        (begin
            (asserts!
                (is-eq tx-sender (get doctor prescription))
                ERR-NOT-AUTHORIZED
            )
            (asserts!
                (is-eq (get refill-status refill-request) "PENDING")
                ERR-REFILL-ALREADY-PROCESSED
            )
            (map-set refill-requests { refill-id: refill-id }
                (merge refill-request { doctor-approval: true })
            )
            (let ((audit-details u"Doctor approved refill request"))
                (log-audit-event (get prescription-id refill-request) "REFILL_DOCTOR_APPROVED" audit-details)
            )
            (try! (check-and-process-refill refill-id))
            (ok true)
        )
    )
)

(define-public (approve-refill-pharmacy (refill-id uint))
    (let (
            (refill-request (unwrap!
                (map-get? refill-requests { refill-id: refill-id })
                ERR-REFILL-NOT-FOUND
            ))
        )
        (begin
            (asserts!
                (is-eq tx-sender (get requesting-pharmacy refill-request))
                ERR-NOT-AUTHORIZED
            )
            (asserts!
                (is-eq (get refill-status refill-request) "PENDING")
                ERR-REFILL-ALREADY-PROCESSED
            )
            (map-set refill-requests { refill-id: refill-id }
                (merge refill-request { pharmacy-approval: true })
            )
            (let ((audit-details u"Pharmacy confirmed refill dispensing"))
                (log-audit-event (get prescription-id refill-request) "REFILL_PHARMACY_APPROVED" audit-details)
            )
            (try! (check-and-process-refill refill-id))
            (ok true)
        )
    )
)

(define-private (check-and-process-refill (refill-id uint))
    (let (
            (refill-request (unwrap!
                (map-get? refill-requests { refill-id: refill-id })
                ERR-REFILL-NOT-FOUND
            ))
        )
        (if (and (get doctor-approval refill-request) (get pharmacy-approval refill-request))
            (process-refill-completion refill-id)
            (ok false)
        )
    )
)

(define-private (process-refill-completion (refill-id uint))
    (let (
            (refill-request (unwrap!
                (map-get? refill-requests { refill-id: refill-id })
                ERR-REFILL-NOT-FOUND
            ))
            (refill-config (unwrap!
                (map-get? prescription-refill-config { prescription-id: (get prescription-id refill-request) })
                ERR-INVALID-REFILL-CONFIG
            ))
            (new-refills-used (+ (get refills-used refill-config) u1))
            (next-eligible (+ stacks-block-height (get days-between-refills refill-config)))
        )
        (begin
            (map-set refill-requests { refill-id: refill-id }
                (merge refill-request {
                    refill-status: "COMPLETED",
                    processed-timestamp: (some stacks-block-height),
                })
            )
            (map-set prescription-refill-config { prescription-id: (get prescription-id refill-request) }
                (merge refill-config {
                    refills-used: new-refills-used,
                    last-refill-timestamp: (some stacks-block-height),
                    next-eligible-refill: (some next-eligible),
                })
            )
            (map-set refill-history 
                { prescription-id: (get prescription-id refill-request), refill-sequence: new-refills-used } {
                refill-id: refill-id,
                dispensing-pharmacy: (get requesting-pharmacy refill-request),
                dispense-timestamp: stacks-block-height,
                quantity-dispensed: (unwrap! (get dispensed-quantity refill-request) ERR-INVALID-REFILL-CONFIG),
                days-early: (if (get is-early-refill refill-request)
                    (calculate-days-early refill-config)
                    u0
                ),
                approval-required: (get requires-doctor-approval refill-config),
                insurance-claim: none,
            })
            (let ((audit-details u"Refill processed and dispensed successfully"))
                (log-audit-event (get prescription-id refill-request) "REFILL_COMPLETED" audit-details)
            )
            (ok true)
        )
    )
)

(define-private (calculate-days-early (refill-config (tuple (max-refills uint) (refills-used uint) (days-between-refills uint) (early-refill-threshold uint) (last-refill-timestamp (optional uint)) (next-eligible-refill (optional uint)) (requires-doctor-approval bool))))
    (match (get last-refill-timestamp refill-config)
        last-refill
            (let ((days-since-last (- stacks-block-height last-refill))
                  (expected-days (get days-between-refills refill-config)))
                (if (< days-since-last expected-days)
                    (- expected-days days-since-last)
                    u0
                )
            )
        u0
    )
)

(define-public (reject-refill (refill-id uint) (rejection-reason (string-utf8 128)))
    (let (
            (refill-request (unwrap!
                (map-get? refill-requests { refill-id: refill-id })
                ERR-REFILL-NOT-FOUND
            ))
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: (get prescription-id refill-request) })
                ERR-INVALID-PRESCRIPTION
            ))
        )
        (begin
            (asserts!
                (or
                    (is-eq tx-sender (get doctor prescription))
                    (is-eq tx-sender (get requesting-pharmacy refill-request))
                    (is-eq tx-sender (var-get contract-owner))
                )
                ERR-NOT-AUTHORIZED
            )
            (asserts!
                (is-eq (get refill-status refill-request) "PENDING")
                ERR-REFILL-ALREADY-PROCESSED
            )
            (map-set refill-requests { refill-id: refill-id }
                (merge refill-request { refill-status: "REJECTED" })
            )
            (let ((audit-details (concat u"Refill rejected: " rejection-reason)))
                (log-audit-event (get prescription-id refill-request) "REFILL_REJECTED" audit-details)
            )
            (ok true)
        )
    )
)

(define-read-only (get-refill-eligibility (prescription-id uint))
    (match (map-get? prescription-refill-config { prescription-id: prescription-id })
        refill-config
            (let (
                    (refills-remaining (- (get max-refills refill-config) (get refills-used refill-config)))
                    (is-eligible (> refills-remaining u0))
                    (next-eligible-date (get next-eligible-refill refill-config))
                    (can-refill-now (match next-eligible-date
                        date (>= stacks-block-height date)
                        true
                    ))
                )
                (ok {
                    eligible: is-eligible,
                    refills-remaining: refills-remaining,
                    can-refill-now: can-refill-now,
                    next-eligible-date: next-eligible-date,
                })
            )
        ERR-INVALID-REFILL-CONFIG
    )
)

(define-read-only (get-refill-request (refill-id uint))
    (map-get? refill-requests { refill-id: refill-id })
)

(define-read-only (get-refill-config (prescription-id uint))
    (map-get? prescription-refill-config { prescription-id: prescription-id })
)

(define-read-only (get-refill-history (prescription-id uint) (refill-sequence uint))
    (map-get? refill-history { prescription-id: prescription-id, refill-sequence: refill-sequence })
)

(define-read-only (get-refill-counter)
    (var-get refill-counter)
)

;; Emergency Override System
(define-map authorized-emergency-responders
    principal
    {
        facility-name: (string-utf8 64),
        facility-type: (string-ascii 32),
        authorized-by: principal,
        authorization-timestamp: uint,
        is-active: bool,
    }
)

(define-map emergency-overrides
    { override-id: uint }
    {
        prescription-id: uint,
        requesting-responder: principal,
        emergency-justification: (string-utf8 256),
        patient-emergency-id: (string-utf8 64),
        override-expiry: uint,
        supervisor-approval: bool,
        supervising-responder: (optional principal),
        override-status: (string-ascii 16),
        creation-timestamp: uint,
        approval-timestamp: (optional uint),
        dispensing-pharmacy: (optional principal),
        emergency-quantity: uint,
    }
)

(define-public (add-emergency-responder
        (responder principal)
        (facility-name (string-utf8 64))
        (facility-type (string-ascii 32))
    )
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (> (len facility-name) u0) ERR-INSUFFICIENT-JUSTIFICATION)
        (map-set authorized-emergency-responders responder {
            facility-name: facility-name,
            facility-type: facility-type,
            authorized-by: tx-sender,
            authorization-timestamp: stacks-block-height,
            is-active: true,
        })
        (ok true)
    )
)

(define-public (deactivate-emergency-responder (responder principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (let (
                (responder-info (unwrap!
                    (map-get? authorized-emergency-responders responder)
                    ERR-NOT-EMERGENCY-RESPONDER
                ))
            )
            (begin
                (map-set authorized-emergency-responders responder
                    (merge responder-info { is-active: false })
                )
                (ok true)
            )
        )
    )
)

(define-read-only (is-emergency-responder (responder principal))
    (match (map-get? authorized-emergency-responders responder)
        responder-info (get is-active responder-info)
        false
    )
)

(define-public (request-emergency-override
        (prescription-id uint)
        (emergency-justification (string-utf8 256))
        (patient-emergency-id (string-utf8 64))
        (emergency-quantity uint)
        (override-duration-blocks uint)
    )
    (let (
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: prescription-id })
                ERR-INVALID-PRESCRIPTION
            ))
            (current-counter (var-get emergency-override-counter))
            (new-override-id (+ current-counter u1))
            (override-expiry (+ stacks-block-height override-duration-blocks))
        )
        (begin
            (asserts! (is-emergency-responder tx-sender) ERR-NOT-EMERGENCY-RESPONDER)
            (asserts! (> (len emergency-justification) u20) ERR-INSUFFICIENT-JUSTIFICATION)
            (asserts! (> emergency-quantity u0) ERR-INVALID-EMERGENCY-OVERRIDE)
            (asserts! (<= override-duration-blocks u4320) ERR-INVALID-EMERGENCY-OVERRIDE) ;; Max 72 hours
            (var-set emergency-override-counter new-override-id)
            (map-set emergency-overrides { override-id: new-override-id } {
                prescription-id: prescription-id,
                requesting-responder: tx-sender,
                emergency-justification: emergency-justification,
                patient-emergency-id: patient-emergency-id,
                override-expiry: override-expiry,
                supervisor-approval: false,
                supervising-responder: none,
                override-status: "PENDING",
                creation-timestamp: stacks-block-height,
                approval-timestamp: none,
                dispensing-pharmacy: none,
                emergency-quantity: emergency-quantity,
            })
            (let ((audit-details u"Emergency override requested for critical patient care"))
                (log-audit-event prescription-id "EMERGENCY_OVERRIDE_REQUESTED" audit-details)
            )
            (ok new-override-id)
        )
    )
)

(define-public (approve-emergency-override
        (override-id uint)
        (supervising-responder (optional principal))
    )
    (let (
            (override-request (unwrap!
                (map-get? emergency-overrides { override-id: override-id })
                ERR-INVALID-EMERGENCY-OVERRIDE
            ))
        )
        (begin
            (asserts!
                (or
                    (is-eq tx-sender (var-get contract-owner))
                    (is-emergency-responder tx-sender)
                )
                ERR-NOT-EMERGENCY-RESPONDER
            )
            (asserts!
                (is-eq (get override-status override-request) "PENDING")
                ERR-OVERRIDE-ALREADY-EXISTS
            )
            (asserts!
                (<= stacks-block-height (get override-expiry override-request))
                ERR-OVERRIDE-EXPIRED
            )
            (map-set emergency-overrides { override-id: override-id }
                (merge override-request {
                    supervisor-approval: true,
                    supervising-responder: supervising-responder,
                    override-status: "APPROVED",
                    approval-timestamp: (some stacks-block-height),
                })
            )
            (let ((audit-details u"Emergency override approved by supervisor"))
                (log-audit-event (get prescription-id override-request) "EMERGENCY_OVERRIDE_APPROVED" audit-details)
            )
            (ok true)
        )
    )
)

(define-public (dispense-emergency-override
        (override-id uint)
        (dispensing-pharmacy principal)
    )
    (let (
            (override-request (unwrap!
                (map-get? emergency-overrides { override-id: override-id })
                ERR-INVALID-EMERGENCY-OVERRIDE
            ))
        )
        (begin
            (asserts! (is-authorized-pharmacy dispensing-pharmacy) ERR-INVALID-PHARMACY)
            (asserts!
                (is-eq (get override-status override-request) "APPROVED")
                ERR-INVALID-EMERGENCY-OVERRIDE
            )
            (asserts!
                (<= stacks-block-height (get override-expiry override-request))
                ERR-OVERRIDE-EXPIRED
            )
            (map-set emergency-overrides { override-id: override-id }
                (merge override-request {
                    override-status: "DISPENSED",
                    dispensing-pharmacy: (some dispensing-pharmacy),
                })
            )
            (let ((audit-details u"Emergency override dispensed to patient"))
                (log-audit-event (get prescription-id override-request) "EMERGENCY_OVERRIDE_DISPENSED" audit-details)
            )
            (ok true)
        )
    )
)

(define-public (reject-emergency-override
        (override-id uint)
        (rejection-reason (string-utf8 128))
    )
    (let (
            (override-request (unwrap!
                (map-get? emergency-overrides { override-id: override-id })
                ERR-INVALID-EMERGENCY-OVERRIDE
            ))
        )
        (begin
            (asserts!
                (or
                    (is-eq tx-sender (var-get contract-owner))
                    (is-emergency-responder tx-sender)
                )
                ERR-NOT-EMERGENCY-RESPONDER
            )
            (asserts!
                (is-eq (get override-status override-request) "PENDING")
                ERR-OVERRIDE-ALREADY-EXISTS
            )
            (map-set emergency-overrides { override-id: override-id }
                (merge override-request { override-status: "REJECTED" })
            )
            (let ((audit-details (concat u"Emergency override rejected: " rejection-reason)))
                (log-audit-event (get prescription-id override-request) "EMERGENCY_OVERRIDE_REJECTED" audit-details)
            )
            (ok true)
        )
    )
)

(define-read-only (get-emergency-override (override-id uint))
    (map-get? emergency-overrides { override-id: override-id })
)

(define-read-only (get-emergency-responder-info (responder principal))
    (map-get? authorized-emergency-responders responder)
)

(define-read-only (get-emergency-override-counter)
    (var-get emergency-override-counter)
)

(define-read-only (verify-emergency-access
        (prescription-id uint)
        (emergency-responder principal)
    )
    (let (
            (prescription (unwrap!
                (map-get? prescriptions { prescription-id: prescription-id })
                ERR-INVALID-PRESCRIPTION
            ))
        )
        (if (is-emergency-responder emergency-responder)
            (ok {
                prescription-valid: true,
                responder-authorized: true,
                can-request-override: true,
                prescription-status: (if (get filled prescription) "FILLED" "AVAILABLE"),
            })
            (ok {
                prescription-valid: true,
                responder-authorized: false,
                can-request-override: false,
                prescription-status: (if (get filled prescription) "FILLED" "AVAILABLE"),
            })
        )
    )
)

