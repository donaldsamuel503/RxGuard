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

(define-data-var contract-owner principal tx-sender)
(define-data-var audit-counter uint u0)
(define-data-var transfer-counter uint u0)

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
