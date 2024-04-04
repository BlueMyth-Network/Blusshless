#pragma once

#include "../../main.h"
#include "../../io/packet/packet.h"
#include "../../world/world.h"
#include "../../world/entity/living/player/player.h"
#include "../listening.h"

extern bool phd_play(ltg_client_t*, pck_packet_t*);

extern bool phd_handle_teleport_confirm(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_query_block_nbt(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_set_difficulty(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_chat_message(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_client_status(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_client_settings(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_tab_complete(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_click_window_button(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_click_window(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_close_window(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_plugin_message(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_edit_book(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_query_entity_nbt(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_interact_entity(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_generate_structure(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_keep_alive(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_lock_difficulty(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_player_position(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_player_position_and_look(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_player_rotation(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_player_movement(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_vehicle_move(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_steer_boat(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_pick_item(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_craft_recipe_request(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_player_abilities(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_player_digging(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_entity_action(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_steer_vehicle(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_pong(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_set_recipe_book_state(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_set_displayed_recipe(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_name_item(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_resource_pack_status(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_advancement_tab(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_select_trade(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_set_beacon_effect(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_held_item_change(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_update_command_block(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_update_command_block_minecart(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_creative_inventory_action(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_update_jigsaw_block(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_update_structure_block(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_update_sign(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_animation(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_spectate(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_player_block_placement(ltg_client_t* client, pck_packet_t* packet);
extern bool phd_handle_use_item(ltg_client_t* client, pck_packet_t* packet);

extern void phd_send_spawn_entity(ltg_client_t*);
extern void phd_send_spawn_experience_orb(ltg_client_t*);
extern void phd_send_spawn_living_entity(ltg_client_t*);
extern void phd_send_spawn_painting(ltg_client_t*);
extern void phd_send_spawn_player(ltg_client_t* client, ent_player_t* player);
extern void phd_send_sculk_vibration_signal(ltg_client_t*);
extern void phd_send_entity_animation(ltg_client_t*);
extern void phd_send_statistics(ltg_client_t*);
extern void phd_send_acknowledge_player_digging(ltg_client_t*);
extern void phd_send_block_break_animation(ltg_client_t*);
extern void phd_send_block_entity_data(ltg_client_t*);
extern void phd_send_block_action(ltg_client_t*);
extern void phd_send_block_change(ltg_client_t*);
extern void phd_send_boss_bar(ltg_client_t*);
extern void phd_send_server_difficulty(ltg_client_t* client);

extern void phd_send_chat_message(ltg_client_t* client, const char* message, size_t message_length, const ltg_uuid_t uuid);
extern void phd_send_system_chat_message(ltg_client_t* client, const char* message, size_t message_length);

extern void phd_send_clear_tiles(ltg_client_t*);
extern void phd_send_tab_complete(ltg_client_t*);
extern void phd_send_declare_commands(ltg_client_t* client);
extern void phd_send_close_window(ltg_client_t*);
extern void phd_send_window_items(ltg_client_t*);
extern void phd_send_player_inventory(ltg_client_t* client);
extern void phd_send_window_property(ltg_client_t*);
extern void phd_send_set_slot(ltg_client_t*);
extern void phd_send_set_cooldown(ltg_client_t*);
extern void phd_send_plugin_message(ltg_client_t* client, const char* identifier, size_t identifier_length, const byte_t* data, size_t data_length);
extern void phd_send_named_sound_effect(ltg_client_t*);
extern void phd_send_disconnect(ltg_client_t* client, const char* message, size_t message_len);
extern void phd_send_entity_status(ltg_client_t* client, ent_entity_t* entity, uint8_t status);
extern void phd_send_explosion(ltg_client_t*);
extern void phd_send_unload_chunk(ltg_client_t* client, wld_chunk_t* chunk);
extern void phd_send_change_game_state(ltg_client_t*);
extern void phd_send_open_horse_window(ltg_client_t*);
extern void phd_send_initialize_world_border(ltg_client_t* client, wld_world_t* world);
extern void phd_send_keep_alive(ltg_client_t* client, uint64_t id);
extern void phd_send_chunk_data_and_update_light(ltg_client_t* client, wld_chunk_t* chunk);
extern void phd_send_effect(ltg_client_t*);
extern void phd_send_particle(ltg_client_t*);
extern void phd_send_update_light(ltg_client_t* client, wld_chunk_t* chunk);
extern void phd_send_join_game(ltg_client_t* client);
extern void phd_send_map_data(ltg_client_t*);
extern void phd_send_trade_list(ltg_client_t*);
extern void phd_send_entity_position(ltg_client_t* client, ent_entity_t* entity, float64_t d_x, float64_t d_y, float64_t d_z);
extern void phd_send_entity_position_and_rotation(ltg_client_t* client, ent_living_entity_t* entity, float64_t d_x, float64_t d_y, float64_t d_z);
extern void phd_send_entity_rotation(ltg_client_t* client, ent_living_entity_t* entity);
extern void phd_send_vehicle_move(ltg_client_t*);
extern void phd_send_open_book(ltg_client_t*);
extern void phd_send_open_window(ltg_client_t*);
extern void phd_send_open_sign_editor(ltg_client_t*);
extern void phd_send_ping(ltg_client_t*);
extern void phd_send_craft_recipe_response(ltg_client_t*);
extern void phd_send_player_abilities(ltg_client_t* client);
extern void phd_send_end_combat_event(ltg_client_t*);
extern void phd_send_enter_combat_event(ltg_client_t*);
extern void phd_send_death_combat_event(ltg_client_t* client, ent_player_t* player, ent_entity_t* killer, const char* message, size_t message_length);

extern void phd_send_player_info_add_players(ltg_client_t* client);
extern void phd_send_player_info_add_player(ltg_client_t* client, ltg_client_t* player);
extern void phd_send_player_info_update_gamemode(ltg_client_t* client, ltg_client_t* player);
// does NOT lock players list, expects it to be locked beforehand
extern void phd_send_player_info_update_latency(ltg_client_t* client);
extern void phd_send_player_info_update_display_name(ltg_client_t* client, ltg_client_t* player);
extern void phd_send_player_info_remove_player(ltg_client_t* client, ltg_uuid_t uuid);

extern void phd_send_face_player(ltg_client_t*);
extern void phd_send_player_position_and_look(ltg_client_t* client);
extern void phd_send_unlock_recipes(ltg_client_t* client);
extern void phd_send_destroy_entity(ltg_client_t* client, ent_entity_t* entity);
extern void phd_send_destroy_entities(ltg_client_t*);
extern void phd_send_remove_entity_effect(ltg_client_t*);
extern void phd_send_resource_pack_send(ltg_client_t*);
extern void phd_send_respawn(ltg_client_t* client, wld_world_t* world, bool keep_metadata);
extern void phd_send_entity_head_look(ltg_client_t* client, ent_living_entity_t* entity);
extern void phd_send_multi_block_change(ltg_client_t*);
extern void phd_send_select_advancement_tab(ltg_client_t*);
extern void phd_send_action_bar(ltg_client_t*);
extern void phd_send_world_border_center(ltg_client_t*);
extern void phd_send_world_border_lerp_size(ltg_client_t*);
extern void phd_send_world_border_size(ltg_client_t*);
extern void phd_send_world_border_warning_delay(ltg_client_t*);
extern void phd_send_world_border_warning_reach(ltg_client_t*);
extern void phd_send_camera(ltg_client_t*);
extern void phd_send_held_item_change(ltg_client_t* client);
extern void phd_send_update_view_position(ltg_client_t* client);
extern void phd_send_update_view_position_to(ltg_client_t* client, int32_t x, int32_t z);
extern void phd_send_update_view_distance(ltg_client_t*);
extern void phd_send_spawn_position(ltg_client_t* client);
extern void phd_send_display_scoreboard(ltg_client_t*);
extern void phd_send_entity_metadata(ltg_client_t*);
extern void phd_send_attach_entity(ltg_client_t*);
extern void phd_send_entity_velocity(ltg_client_t*);
extern void phd_send_entity_equipment(ltg_client_t*);
extern void phd_send_set_experience(ltg_client_t* client);
extern void phd_send_update_health(ltg_client_t* client);
extern void phd_send_scoreboard_objective(ltg_client_t*);
extern void phd_send_set_passengers(ltg_client_t*);
extern void phd_send_teams(ltg_client_t*);
extern void phd_send_update_score(ltg_client_t*);
extern void phd_send_update_simulation_distance(ltg_client_t*);
extern void phd_send_set_tile_subtile(ltg_client_t*);
extern void phd_send_time_update(ltg_client_t* client, wld_world_t* world);
extern void phd_send_set_title_text(ltg_client_t*);
extern void phd_send_set_title_times(ltg_client_t*);
extern void phd_send_entity_sound_effect(ltg_client_t*);
extern void phd_send_sound_effect(ltg_client_t*);
extern void phd_send_stop_sound(ltg_client_t*);
extern void phd_send_player_list_header_and_footer(ltg_client_t*);
extern void phd_send_nbt_query_response(ltg_client_t*);
extern void phd_send_collect_item(ltg_client_t*);
extern void phd_send_entity_teleport(ltg_client_t* client, ent_entity_t* entity);
extern void phd_send_living_entity_teleport(ltg_client_t* client, ent_living_entity_t* entity);
extern void phd_send_advancements(ltg_client_t*);
extern void phd_send_entity_properties(ltg_client_t*);
extern void phd_send_entity_effect(ltg_client_t*);
extern void phd_send_declare_recipes(ltg_client_t* client);
extern void phd_send_tags(ltg_client_t* client);

static inline void phd_update_send_entity(ltg_client_t* client, ent_entity_t* entity) {
	if (entity != ent_player_get_entity(ltg_client_get_entity(client))) {
		switch (ent_get_type(entity)) {
			case ent_player: {
				phd_send_spawn_player(client, (ent_player_t*) entity);
				phd_send_entity_head_look(client, (ent_living_entity_t*) entity);
			} break;
			default: {
				// Do something eventually
			} break;
		}
	}
}

static inline void phd_update_subscribe_chunk(ltg_client_t* client, wld_chunk_t* chunk) {

	phd_send_chunk_data_and_update_light(client, chunk);
	wld_subscribe_chunk(chunk, ltg_client_get_id(client));

	// send chunk entities
	uint32_t entity_length = wld_chunk_get_entity_length(chunk);
	for (uint32_t i = 0; i < entity_length; ++i) {
		ent_entity_t* entity = wld_chunk_get_entity(chunk, i);
		if (entity != NULL) {
			phd_update_send_entity(client, entity);
		}
	}
}

static inline void phd_update_unsubscribe_chunk(ltg_client_t* client, wld_chunk_t* chunk) {
	wld_unsubscribe_chunk(chunk, ltg_client_get_id(client));
	//phd_send_unload_chunk(client, chunk); // TODO not send this packet
}

extern void phd_update_sent_chunks(ltg_client_t* client);
extern void phd_update_sent_chunks_view_distance(ltg_client_t* client, uint8_t view_distance);
extern void phd_update_sent_chunks_move(ltg_client_t* client, const wld_chunk_t* old_chunk);
extern void phd_update_sent_chunks_teleport(ltg_client_t* client, const wld_chunk_t* old_chunk);
extern void phd_update_sent_chunks_remove(ltg_client_t* client, const wld_chunk_t* chunk);
extern void phd_update_sent_chunks_leave(ltg_client_t* client);

extern void phd_update_respawn(ltg_client_t* client);