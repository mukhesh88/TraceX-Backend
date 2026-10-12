package com.tracex.repository;

import com.tracex.entity.ScanRecord;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface ScanRecordRepository extends JpaRepository<ScanRecord, Long> {

    Page<ScanRecord> findAllByOrderByTimestampDesc(Pageable pageable);

    long countByStatus(String status);

    @Query("SELECT AVG(s.inferenceLatencyMs) FROM ScanRecord s")
    Double findAverageLatency();
}
