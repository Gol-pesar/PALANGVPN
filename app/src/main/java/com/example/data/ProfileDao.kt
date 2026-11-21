package com.example.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface ProfileDao {

    @Query("SELECT * FROM server_profiles ORDER BY isSelected DESC, updatedAt DESC")
    fun observeProfiles(): Flow<List<ServerProfileEntity>>

    @Query("SELECT * FROM server_profiles WHERE isSelected = 1 LIMIT 1")
    fun observeSelectedProfile(): Flow<ServerProfileEntity?>

    @Query("SELECT * FROM server_profiles WHERE isSelected = 1 LIMIT 1")
    suspend fun getSelectedProfileOnce(): ServerProfileEntity?

    @Query("SELECT COUNT(*) FROM server_profiles")
    suspend fun countProfiles(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(profile: ServerProfileEntity): Long

    @Update
    suspend fun update(profile: ServerProfileEntity)

    @Query("UPDATE server_profiles SET isSelected = 0")
    suspend fun clearSelection()

    @Query("UPDATE server_profiles SET isSelected = 1 WHERE id = :id")
    suspend fun markSelected(id: Long)

    @Transaction
    suspend fun selectProfile(id: Long) {
        clearSelection()
        markSelected(id)
    }

    @Query("UPDATE server_profiles SET lastLatencyMs = :latencyMs WHERE id = :id")
    suspend fun updateLatency(id: Long, latencyMs: Int?)

    @Query("DELETE FROM server_profiles WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT * FROM server_profiles ORDER BY updatedAt DESC LIMIT 1")
    suspend fun getMostRecentProfile(): ServerProfileEntity?
}
