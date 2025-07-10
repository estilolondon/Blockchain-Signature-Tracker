;; Digital Document Authentication & Multi-Signature Verification System Smart Contract
;; 
;; A comprehensive blockchain-based system for secure document authentication,
;; cryptographic signature verification, and multi-party authorization tracking.
;; Enables tamper-proof document registration, lifecycle management, and
;; legally-binding digital signature workflows for enterprise and legal use cases.

;; CORE DATA STRUCTURES

;; Central document registry with metadata and signature tracking
(define-map authenticated-documents
  { document-hash: (buff 32) }
  {
    original-creator: principal,
    document-name: (string-utf8 256),
    document-summary: (string-utf8 1024),
    created-at: uint,
    current-status: (string-utf8 20),
    validated-signatures: uint
  }
)

;; Individual signature verification records
(define-map signature-verification-records
  { 
    document-hash: (buff 32),
    signer-principal: principal
  }
  {
    digital-signature: (buff 65),
    signed-at: uint,
    signature-context: (string-utf8 256),
    is-signature-valid: bool
  }
)

;; Public key registry for cryptographic verification
(define-map registered-public-keys
  { principal-owner: principal }
  { compressed-secp256k1-key: (buff 33) }
)

;; Global system metrics
(define-data-var total-authenticated-documents uint u0)

;; ERROR CODES AND SYSTEM CONSTANTS

;; Authentication and authorization errors
(define-constant ERR-UNAUTHORIZED-OPERATION (err u401))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u404))
(define-constant ERR-DOCUMENT-ALREADY-REGISTERED (err u409))
(define-constant ERR-INVALID-SIGNATURE-DATA (err u400))
(define-constant ERR-DUPLICATE-SIGNATURE-DETECTED (err u409))
(define-constant ERR-DOCUMENT-ACCESS-REVOKED (err u403))
(define-constant ERR-PUBLIC-KEY-NOT-REGISTERED (err u404))
(define-constant ERR-MALFORMED-PUBLIC-KEY (err u400))
(define-constant ERR-INVALID-PARAMETER-INPUT (err u400))

;; Document lifecycle status constants
(define-constant document-status-active u"active")
(define-constant document-status-revoked u"revoked")

;; Cryptographic key format validation constants
(define-constant secp256k1-prefix-even 0x02)
(define-constant secp256k1-prefix-odd 0x03)
(define-constant max-batch-verification-size u10)

;; DOCUMENT QUERY AND VALIDATION FUNCTIONS

;; Retrieve complete document authentication record
(define-read-only (fetch-document-record (document-hash (buff 32)))
  (map-get? authenticated-documents { document-hash: document-hash })
)

;; Check if document exists in authentication registry
(define-read-only (is-document-authenticated (document-hash (buff 32)))
  (is-some (map-get? authenticated-documents { document-hash: document-hash }))
)

;; Get signature verification details for specific document and signer
(define-read-only (fetch-signature-record (document-hash (buff 32)) (signer-principal principal))
  (map-get? signature-verification-records { document-hash: document-hash, signer-principal: signer-principal })
)

;; Verify if principal has provided valid signature for document
(define-read-only (has-principal-signed (document-hash (buff 32)) (signer-principal principal))
  (is-some (map-get? signature-verification-records { document-hash: document-hash, signer-principal: signer-principal }))
)

;; Get total validated signatures for specific document
(define-read-only (count-document-signatures (document-hash (buff 32)))
  (let ((document-record (fetch-document-record document-hash)))
    (if (is-some document-record)
      (get validated-signatures (unwrap-panic document-record))
      u0
    )
  )
)

;; Retrieve registered public key for principal
(define-read-only (fetch-principal-public-key (principal-owner principal))
  (map-get? registered-public-keys { principal-owner: principal-owner })
)

;; Get total system-wide authenticated documents
(define-read-only (get-total-authenticated-documents)
  (var-get total-authenticated-documents)
)

;; CRYPTOGRAPHIC VERIFICATION FUNCTIONS

;; Verify digital signature against message hash and public key
(define-read-only (verify-signature-authenticity 
    (message-hash (buff 32))
    (digital-signature (buff 65))
    (compressed-secp256k1-key (buff 33)))
  (is-eq (secp256k1-recover? message-hash digital-signature) (ok compressed-secp256k1-key))
)

;; Validate secp256k1 compressed public key format
(define-read-only (is-valid-secp256k1-format (compressed-secp256k1-key (buff 33)))
  (let (
    (key-prefix (unwrap-panic (element-at? compressed-secp256k1-key u0)))
  )
    (or 
      (is-eq key-prefix secp256k1-prefix-even)
      (is-eq key-prefix secp256k1-prefix-odd)
    )
  )
)

;; INPUT VALIDATION UTILITIES

;; Validate non-empty string input
(define-read-only (is-string-non-empty (input-string (string-utf8 1024)))
  (not (is-eq input-string u""))
)

;; Validate document summary format (can be empty)
(define-read-only (is-valid-summary-format (document-summary (string-utf8 1024)))
  true ;; Type constraint ensures valid UTF-8
)

;; PUBLIC KEY MANAGEMENT

;; Register cryptographic public key for signature verification
(define-public (register-signing-key (compressed-secp256k1-key (buff 33)))
  (begin
    (asserts! (is-valid-secp256k1-format compressed-secp256k1-key) ERR-MALFORMED-PUBLIC-KEY)
    
    (map-set registered-public-keys
      { principal-owner: tx-sender }
      { compressed-secp256k1-key: compressed-secp256k1-key }
    )
    (ok true)
  )
)

;; DOCUMENT LIFECYCLE MANAGEMENT

;; Register new document for authentication and signature tracking
(define-public (authenticate-new-document 
    (document-hash (buff 32))
    (document-name (string-utf8 256))
    (document-summary (string-utf8 1024)))
  (let ((current-timestamp (unwrap-panic (get-block-info? time (- block-height u1)))))
    (asserts! (is-string-non-empty document-name) ERR-INVALID-PARAMETER-INPUT)
    (asserts! (is-valid-summary-format document-summary) ERR-INVALID-PARAMETER-INPUT)
    
    (if (is-document-authenticated document-hash)
      ERR-DOCUMENT-ALREADY-REGISTERED
      (begin
        (map-set authenticated-documents
          { document-hash: document-hash }
          {
            original-creator: tx-sender,
            document-name: document-name,
            document-summary: document-summary,
            created-at: current-timestamp,
            current-status: document-status-active,
            validated-signatures: u0
          }
        )
        (var-set total-authenticated-documents (+ (var-get total-authenticated-documents) u1))
        (ok true)
      )
    )
  )
)

;; Update document metadata (creator authorization required)
(define-public (modify-document-metadata
    (document-hash (buff 32))
    (updated-document-name (string-utf8 256))
    (updated-document-summary (string-utf8 1024)))
  (let ((document-record (fetch-document-record document-hash)))
    (asserts! (is-some document-record) ERR-DOCUMENT-NOT-FOUND)
    (asserts! (is-string-non-empty updated-document-name) ERR-INVALID-PARAMETER-INPUT)
    (asserts! (is-valid-summary-format updated-document-summary) ERR-INVALID-PARAMETER-INPUT)
    
    (let ((document-data (unwrap-panic document-record)))
      (asserts! (is-eq tx-sender (get original-creator document-data)) ERR-UNAUTHORIZED-OPERATION)
      
      (map-set authenticated-documents
        { document-hash: document-hash }
        (merge document-data { 
          document-name: updated-document-name,
          document-summary: updated-document-summary
        })
      )
      (ok true)
    )
  )
)

;; Revoke document access (creator authorization required)
(define-public (revoke-document-access (document-hash (buff 32)))
  (let ((document-record (fetch-document-record document-hash)))
    (asserts! (is-some document-record) ERR-DOCUMENT-NOT-FOUND)
    
    (let ((document-data (unwrap-panic document-record)))
      (asserts! (is-eq tx-sender (get original-creator document-data)) ERR-UNAUTHORIZED-OPERATION)
      
      (map-set authenticated-documents
        { document-hash: document-hash }
        (merge document-data { current-status: document-status-revoked })
      )
      (ok true)
    )
  )
)

;; DIGITAL SIGNATURE PROCESSING

;; Process and verify digital signature for document
(define-public (process-document-signature 
    (document-hash (buff 32))
    (digital-signature (buff 65))
    (signature-context (string-utf8 256)))
  (let (
    (document-record (fetch-document-record document-hash))
    (current-timestamp (unwrap-panic (get-block-info? time (- block-height u1))))
    (signer-key-record (fetch-principal-public-key tx-sender))
  )
    (asserts! (is-some document-record) ERR-DOCUMENT-NOT-FOUND)
    (asserts! (is-some signer-key-record) ERR-PUBLIC-KEY-NOT-REGISTERED)
    (asserts! (is-string-non-empty signature-context) ERR-INVALID-PARAMETER-INPUT)
    
    (let (
      (document-data (unwrap-panic document-record))
      (signer-public-key (get compressed-secp256k1-key (unwrap-panic signer-key-record)))
      (combined-hash (sha256 (concat document-hash (sha256 (unwrap! (to-consensus-buff? signature-context) ERR-INVALID-SIGNATURE-DATA)))))
    )
      (asserts! (is-eq (get current-status document-data) document-status-active) ERR-DOCUMENT-ACCESS-REVOKED)
      (asserts! (not (has-principal-signed document-hash tx-sender)) ERR-DUPLICATE-SIGNATURE-DETECTED)
      (asserts! (verify-signature-authenticity combined-hash digital-signature signer-public-key) ERR-INVALID-SIGNATURE-DATA)
      
      (map-set signature-verification-records
        { document-hash: document-hash, signer-principal: tx-sender }
        { 
          digital-signature: digital-signature,
          signed-at: current-timestamp,
          signature-context: signature-context,
          is-signature-valid: true
        }
      )
      
      (map-set authenticated-documents
        { document-hash: document-hash }
        (merge document-data { validated-signatures: (+ (get validated-signatures document-data) u1) })
      )
      
      (ok true)
    )
  )
)

;; Invalidate signature (creator authorization required)
(define-public (invalidate-signature
    (document-hash (buff 32))
    (target-signer principal))
  (let (
    (document-record (fetch-document-record document-hash))
    (signature-record (fetch-signature-record document-hash target-signer))
  )
    (asserts! (is-some document-record) ERR-DOCUMENT-NOT-FOUND)
    (asserts! (is-some signature-record) ERR-INVALID-SIGNATURE-DATA)
    
    (let (
      (document-data (unwrap-panic document-record))
      (signature-data (unwrap-panic signature-record))
    )
      (asserts! (is-eq tx-sender (get original-creator document-data)) ERR-UNAUTHORIZED-OPERATION)
      
      (if (get is-signature-valid signature-data)
        (map-set authenticated-documents
          { document-hash: document-hash }
          (merge document-data { validated-signatures: (- (get validated-signatures document-data) u1) })
        )
        true
      )
      
      (map-set signature-verification-records
        { document-hash: document-hash, signer-principal: target-signer }
        (merge signature-data { is-signature-valid: false })
      )
      (ok true)
    )
  )
)

;; BATCH SIGNATURE VERIFICATION

;; Verify multiple signatures for document (batch processing)
(define-public (verify-batch-signatures
    (document-hash (buff 32))
    (signer-principals (list 10 principal)))
  (let ((document-record (fetch-document-record document-hash)))
    (asserts! (is-some document-record) ERR-DOCUMENT-NOT-FOUND)
    
    (let ((document-data (unwrap-panic document-record)))
      (asserts! (is-eq (get current-status document-data) document-status-active) ERR-DOCUMENT-ACCESS-REVOKED)
      
      (ok (and
        (or (is-eq (len signer-principals) u0) 
          (and
            (or (< (len signer-principals) u1) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u0))))
            (or (< (len signer-principals) u2) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u1))))
            (or (< (len signer-principals) u3) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u2))))
            (or (< (len signer-principals) u4) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u3))))
            (or (< (len signer-principals) u5) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u4))))
            (or (< (len signer-principals) u6) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u5))))
            (or (< (len signer-principals) u7) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u6))))
            (or (< (len signer-principals) u8) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u7))))
            (or (< (len signer-principals) u9) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u8))))
            (or (< (len signer-principals) u10) (has-principal-signed document-hash (unwrap-panic (element-at signer-principals u9))))
          )
        )
      ))
    )
  )
)