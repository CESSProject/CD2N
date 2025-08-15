use super::*;
use std::collections::HashMap;

pub async fn supplier_data_audit(
    State(state): State<CD2NState>,
    mut multipart: Multipart,
) -> Result<Json<SupplierDataAuditResponse>, AppError> {
    let mut file_data = Vec::new();
    let mut cid = String::new();
    let mut user_acc = String::new();
    let mut key = Vec::new();
    let mut nonce = Vec::new();
    let mut supplier_acc = String::new();
    let mut request_id = String::new();
    let mut user_sign = Vec::new();
    system_initialize(state.need_handover.lock().await.clone())?;

    while let Some(field) = multipart.next_field().await.unwrap() {
        if let Some(name) = field.name() {
            match name {
                "file" => {
                    file_data = field
                        .bytes()
                        .await
                        .map_err(|e| {
                            return_error(
                                anyhow!("The input file is incorrect:{:?}", e.to_string()),
                                StatusCode::BAD_REQUEST,
                            )
                        })?
                        .to_vec();
                }
                "cid" => {
                    cid = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input cid is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "user_acc" => {
                    user_acc = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input user_acc is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "key" => {
                    key = hex::decode(&field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input key is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?)
                    .map_err(|e| {
                        return_error(
                            anyhow!("Error when parsing key:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "nonce" => {
                    nonce = hex::decode(&field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input nonce is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?)
                    .map_err(|e| {
                        return_error(
                            anyhow!("Error when parsing nonce:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "supplier_acc" => {
                    supplier_acc = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input supplier_acc is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "request_id" => {
                    request_id = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input request_id is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "user_sign" => {
                    user_sign = hex::decode(&field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input user_sign is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?)
                    .map_err(|e| {
                        return_error(
                            anyhow!("Error when parsing user_sign:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                other => {
                    return Err(return_error(
                        anyhow!(
                            "Unable to identify, please do not pass in useless fields:{:?}",
                            other
                        ),
                        StatusCode::BAD_REQUEST,
                    ));
                }
            }
        }
    }

    //Check the request is from the user indeed.
    let user_walllet_pbk = crate::utils::wallet::restore_public_key_from_golang_signature(
        user_sign.clone().try_into().map_err(|_| {
            return_error(
                anyhow!("The length of user_sign must be 65"),
                StatusCode::BAD_REQUEST,
            )
        })?,
        request_id.clone().as_bytes(),
    )
    .map_err(|e| return_error(e, StatusCode::BAD_REQUEST))?;

    if !crate::utils::wallet::convert_public_key_to_eth_address(user_walllet_pbk)
        .map_err(|e| return_error(e, StatusCode::BAD_REQUEST))?
        .eq(&user_acc.clone().to_uppercase())
    {
        return Err(return_error(
            anyhow!("The user_sign is not from the user :{:?}", user_acc.clone()),
            StatusCode::BAD_REQUEST,
        ));
    }

    //Set the request into bloom filter. Preventing duplicate requests.
    if state
        .bloom
        .clone()
        .lock()
        .await
        .check_value(request_id.clone())
    {
        return Err(return_error(
            anyhow!("This request:{:?} has been submitted before!", request_id),
            StatusCode::BAD_REQUEST,
        ));
    };
    state
        .bloom
        .clone()
        .lock()
        .await
        .insert_value(request_id.clone());

    //Try to decrypt the data with the shared secret
    let data_provider_secp256k1_pubkey = key;
    let wallet = state.wallet.lock().await.clone();
    let data = if data_provider_secp256k1_pubkey.len() != 0 {
        let shared_secret = wallet
            .ecdh_agreement(data_provider_secp256k1_pubkey.try_into().map_err(|_| {
                return_error(
                    anyhow!("Invalid data provider public key,Please have a check"),
                    StatusCode::BAD_REQUEST,
                )
            })?)
            .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

        let data = wallet
            .decrypt_data_with_shared_secret_and_nonce(
                &file_data,
                shared_secret,
                &nonce.try_into().map_err(|_| {
                    return_error(
                        anyhow!("The length of nonce must be 12!"),
                        StatusCode::BAD_REQUEST,
                    )
                })?,
            )
            .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

        data
    } else {
        file_data
    };

    // Compute the data cid and compare it with the one in the request
    let data_cid = crate::utils::ipfs::compute_ipfs_cid_from_bytes(data.clone())
        .map_err(|e: anyhow::Error| return_error(e, StatusCode::BAD_REQUEST))?;

    if cid != data_cid {
        return Err(return_error(
            anyhow!("The decrypted data is not match the cid in the request!"),
            StatusCode::BAD_REQUEST,
        ));
    }

    // Get reward record in safe storage file.
    let mut incentive_record_storage_guard = state.incentive_record_storage.lock().await;

    let mut previous_seal_data: RewardDatabase = incentive_record_storage_guard
        .unseal_data()
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    //Get the user's total used traffic
    let user_used_traffic = match previous_seal_data.users_supplier_map.get_mut(&user_acc) {
        Some(record_map) => {
            let new_reward: i64 =
                if let Some(reward_record) = record_map.get(TOTAL_USER_USED_TRAFFIC) {
                    reward_record.total_reward
                } else {
                    return Err(return_error(
                        anyhow!("[🐞]The user's total used traffic is not found in the storage!"),
                        StatusCode::BAD_REQUEST,
                    ));
                };
            new_reward
        }
        None => 0,
    };

    let contract = state.contract.lock().await.clone();
    let user_total_purchased_traffic = contract
        .get_user_total_traffic(&wallet.eth_public_address, &user_acc)
        .await
        .map_err(|e| {
            return_error(
                anyhow!("Failed when get user total traffic from contract:{:?}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    //Check user's traffic enough or not.
    let left_download_traffic =
        user_total_purchased_traffic - data.len() as i64 - user_used_traffic;

    if left_download_traffic < 0 {
        return Err(return_error(
            anyhow!("The user's traffic is not enough!"),
            StatusCode::FORBIDDEN,
        ));
    }

    let latest_block_number = contract
        .get_current_block_number()
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
    match previous_seal_data.users_supplier_map.get_mut(&user_acc) {
        Some(record_map) => {
            let supplier_new_reward_record =
                if let Some(reward_record) = record_map.get(&supplier_acc) {
                    SupplierReward {
                        total_reward: data.len() as i64 + reward_record.total_reward,
                        last_updated_block_number: latest_block_number,
                    }
                } else {
                    SupplierReward {
                        total_reward: data.len() as i64,
                        last_updated_block_number: latest_block_number,
                    }
                };

            let user_new_used_traffic_record =
                if let Some(reward_record) = record_map.get(TOTAL_USER_USED_TRAFFIC) {
                    SupplierReward {
                        total_reward: data.len() as i64 + reward_record.total_reward,
                        last_updated_block_number: latest_block_number,
                    }
                } else {
                    SupplierReward {
                        total_reward: data.len() as i64,
                        last_updated_block_number: latest_block_number,
                    }
                };

            record_map.insert(supplier_acc.clone(), supplier_new_reward_record);
            record_map.insert(
                TOTAL_USER_USED_TRAFFIC.to_string(),
                user_new_used_traffic_record,
            );
        }
        None => {
            let mut new_record_map = HashMap::new();
            let new_reward = SupplierReward {
                total_reward: data.len() as i64,
                last_updated_block_number: latest_block_number,
            };
            new_record_map.insert(supplier_acc.clone(), new_reward.clone());
            new_record_map.insert(TOTAL_USER_USED_TRAFFIC.to_string(), new_reward);

            previous_seal_data
                .users_supplier_map
                .insert(user_acc.clone(), new_record_map);
        }
    };
    println!(
        "save reward record:{:?}",
        previous_seal_data.users_supplier_map.get(&user_acc)
    );
    incentive_record_storage_guard
        .seal_data(&previous_seal_data)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let response = SupplierDataAuditResponse {
        msg: String::from("success"),
        data,
    };

    Ok(Json(response))
}

pub async fn query_information(
    State(state): State<CD2NState>,
) -> Result<Json<QueryInformationResponse>, AppError> {
    system_initialize(state.need_handover.lock().await.clone())?;
    let wallet = state.wallet.lock().await.clone();
    let response = QueryInformationResponse {
        eth_address: wallet.eth_public_address.clone(),
        secp256k1_public_key: wallet.public_key.clone(),
    };
    Ok(Json(response))
}

pub async fn download_traffic_query(
    State(state): State<CD2NState>,
    Json(params): Json<QueryDownloadTraffic>,
) -> Result<Json<QueryDownloadTrafficResponse>, AppError> {
    system_initialize(state.need_handover.lock().await.clone())?;
    let contract = state.contract.lock().await.clone();
    let wallet = state.wallet.lock().await.clone();

    let user_total_purchased_traffic = contract
        .get_user_total_traffic(&wallet.eth_public_address, &params.user_eth_address)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let mut incentive_record_storage_guard = state.incentive_record_storage.lock().await;

    let mut previous_seal_data: RewardDatabase = incentive_record_storage_guard
        .unseal_data()
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    //Get the user's total used traffic
    let user_used_traffic = match previous_seal_data
        .users_supplier_map
        .get_mut(&params.user_eth_address)
    {
        Some(record_map) => {
            let user_used_traffic: i64 =
                if let Some(reward_record) = record_map.get(TOTAL_USER_USED_TRAFFIC) {
                    reward_record.total_reward
                } else {
                    return Err(return_error(
                        anyhow!("[🐞]The user's total used traffic is not found in the storage!"),
                        StatusCode::BAD_REQUEST,
                    ));
                };
            user_used_traffic
        }
        None => 0,
    };

    let response = QueryDownloadTrafficResponse {
        user_eth_address: params.user_eth_address,
        left_user_download_traffic: user_total_purchased_traffic - user_used_traffic,
    };
    Ok(Json(response))
}

pub async fn test_echo(
    State(_state): State<CD2NState>,
    Json(_params): Json<TestEcho>,
) -> Result<Json<TestEchoResponse>, AppError> {
    let response = TestEchoResponse {};
    Ok(Json(response))
}
