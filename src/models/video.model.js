import mongoose, { Schema, model } from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const videoSchema = new Schema(
  {
    videoFile: {
      type: String, //cloudnary url
      required: [true, "VideoFile is required!!! "],
    },
    thumbnail: {
      type: String, //cloudnary url
      required: [true, "Thumbnail is required!!! "],
    },
    title: {
      type: String,
      required: [true, "Title is required!!! "],
    },
    description: {
      type: String,
      required: [true, "Description is required!!! "],
    },
    duration: {
      type: Number,
      required: [true, "Duration is required!!! "],
    },
    views: {
      type: Number,
      default: 0,
    },
    isPublished: {
      type: Boolean,
      default: true,
    },
    owner: {
      type: Schema.Types.ObjectId,
      ref: "User",
    },
  },
  {
    timestamps: true,
  }
);

videoSchema.plugin(mongooseAggregatePaginate);

export default Video = model("Video", videoSchema);
