#include "board.h"
#include "handlers.h"
#include "../motor.h"
#include "../util/vector.h"

// TODO keep track of job traffic (increases everytime jobs aren't completed, decreases everytime they are)

// default handler vectors
UTL_VECTOR_DEFAULT(job_keep_alive_handlers, job_handler_t, 
	job_handle_keep_alive
);
UTL_VECTOR_DEFAULT(job_global_chat_message_handlers, job_handler_t,
	job_handle_global_chat_message
);
UTL_VECTOR_DEFAULT(job_player_join_handlers, job_handler_t,
	job_handle_player_join
);
UTL_VECTOR_DEFAULT(job_player_leave_handlers, job_handler_t,
	job_handle_player_leave
);
UTL_VECTOR_DEFAULT(job_send_update_ping_handlers, job_handler_t,
	job_handle_send_update_ping
);
UTL_VECTOR_DEFAULT(job_tick_region_handlers, job_handler_t,
	job_handle_tick_region
);
UTL_VECTOR_DEFAULT(job_unload_region_handlers, job_handler_t,
	job_handle_unload_region
);
UTL_VECTOR_DEFAULT(job_dig_block_handlers, job_handler_t,
	job_handle_dig_block
);
UTL_VECTOR_DEFAULT(job_entity_move_handlers, job_handler_t,
	job_handle_entity_move
);
UTL_VECTOR_DEFAULT(job_entity_teleport_handlers, job_handler_t,
	job_handle_entity_teleport
);
UTL_VECTOR_DEFAULT(job_living_entity_look_handlers, job_handler_t,
	job_handle_living_entity_look
);
UTL_VECTOR_DEFAULT(job_living_entity_move_look_handlers, job_handler_t,
	job_handle_living_entity_move_look
);
UTL_VECTOR_DEFAULT(job_living_entity_teleport_look_handlers, job_handler_t,
	job_handle_living_entity_teleport_look
);
UTL_VECTOR_DEFAULT(job_living_entity_damage_handlers, job_handler_t,
	job_handle_living_entity_damage
);
UTL_VECTOR_DEFAULT(job_tick_world_handlers, job_handler_t,
	job_handle_tick_world
);

UTL_VECTOR_DEFAULT(job_handlers, utl_vector_t*,
	&job_keep_alive_handlers,
	&job_global_chat_message_handlers,
	&job_player_join_handlers,
	&job_player_leave_handlers,
	&job_send_update_ping_handlers,
	&job_tick_region_handlers,
	&job_unload_region_handlers,
	&job_dig_block_handlers,
	&job_entity_move_handlers,
	&job_entity_teleport_handlers,
	&job_living_entity_look_handlers,
	&job_living_entity_move_look_handlers,
	&job_living_entity_teleport_look_handlers,
	&job_living_entity_damage_handlers,
	&job_tick_world_handlers,
);

job_board_t job_board = {
	.queue = {
		.lock = PTHREAD_MUTEX_INITIALIZER,
		.wait = PTHREAD_COND_INITIALIZER,
		.list = UTL_LIST_INITIALIZER(uint32_t)
	},
	.heap = {
		.lock = PTHREAD_MUTEX_INITIALIZER,
		.jobs = UTL_ID_VECTOR_INITIALIZER(job_work_t)
	}
};

uint32_t job_new(job_type_t type, const job_payload_t payload) {

	const job_work_t init = {
		.type = type,
		.payload = payload
	};

	uint32_t id = 0;

	with_lock (&job_board.heap.lock) {

		id = utl_id_vector_push(&job_board.heap.jobs, &init);

	}

	return id;

}

void job_add_handler(job_type_t job, job_handler_t handler) {
	
	utl_vector_push(utl_vector_get(&job_handlers, job), &handler);

}

void job_handle(uint32_t id) {

	job_type_t type = job_count;
	job_payload_t payload = { .client = NULL };
	with_lock (&job_board.heap.lock) {
		job_work_t* work = utl_id_vector_get(&job_board.heap.jobs, id);
		if (work == NULL || work->canceled) {
			pthread_mutex_unlock(&job_board.heap.lock);
			return;
		}
		type = work->type;
		payload = work->payload;
	}

	utl_vector_t* work_handlers = UTL_VECTOR_GET_AS(utl_vector_t*, &job_handlers, type);

	if (work_handlers != NULL) {

		for (size_t i = 0; i < work_handlers->size; ++i) {

			job_handler_t handler = UTL_VECTOR_GET_AS(job_handler_t, work_handlers, i);
			if (!handler(&payload)) {
				break;
			}

		}

	}

	job_free(id);

}

void job_add(uint32_t id) {
	
	job_work_t* work = utl_id_vector_get(&job_board.heap.jobs, id);

	work->on_board++;

	with_lock (&job_board.queue.lock) {
		utl_list_push(&job_board.queue.list, &id);
	}

	with_lock (&job_board.queue.lock) {
		pthread_cond_signal(&job_board.queue.wait);
	}

}

void job_resume() {

	with_lock (&job_board.queue.lock) {
		pthread_cond_broadcast(&job_board.queue.wait);
	}

}

void job_free(uint32_t id) {

	with_lock (&job_board.heap.lock) {
		job_work_t* work = utl_id_vector_get(&job_board.heap.jobs, id);

		work->on_board--;

		if (work->repeat || work->on_board != 0) {
			pthread_mutex_unlock(&job_board.heap.lock);
			return;
		}

		utl_id_vector_remove(&job_board.heap.jobs, id);
	}

}

uint32_t job_get() {

	uint32_t job = 0;

	// wait for jobs
	with_lock (&job_board.queue.lock) {
	
		while (job_board.queue.list.length == 0) {
		
			if (sky_get_status() == sky_stopping) {

				pthread_mutex_unlock(&job_board.queue.lock);

				return 0;

			}

			pthread_cond_wait(&job_board.queue.wait, &job_board.queue.lock);
		
		}
		
		memcpy(&job, utl_list_first(&job_board.queue.list), sizeof(uint32_t));
		utl_list_shift(&job_board.queue.list);

	}

	return job;

}

size_t job_get_count() {

	size_t length = 0;

	with_lock (&job_board.queue.lock) {
		length = job_board.queue.list.length;
	}

	return length;

}

job_type_t job_get_type(uint32_t job) {

	job_type_t type = job_count;

	with_lock (&job_board.heap.lock) {
		job_work_t* work = utl_id_vector_get(&job_board.heap.jobs, job);
		type = work->type;
	}

	return type;

}

void job_work(sky_worker_t* worker) {

	const uint32_t job = job_get();
	worker->job = job;
	job_handle(job);

}